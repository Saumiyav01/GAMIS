"""Evidence sanitization boundary (P2).

Produces a SANITIZED DERIVATIVE of evidence content for display / downstream model input. It never edits
the original: the original EvidenceItem, its content and its integrity_digest are left untouched, and the
derivative carries its own, differently named digest. Sanitization is pattern based and therefore
incomplete; it is not authorization and not a prompt-injection defence. Suspicious instructions are only
MARKED as untrusted - nothing here ever acts on evidence content.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Any, Literal, Mapping, Self

from pydantic import Field, model_validator

from gamis.schemas.common import (FrozenJson, Identifier, Sha256Hex, ShortText, StrictModel, freeze_json)
from gamis.schemas.evidence import EvidenceItem
from gamis.security.digest import canonical_digest

SANITIZER_VERSION = "1.0.0"
UNTRUSTED_OPEN, UNTRUSTED_CLOSE = "[[UNTRUSTED-INSTRUCTION: ", "]]"


class FindingKind(StrEnum):
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"
    PII = "PII"
    CONTROL_CHARACTER = "CONTROL_CHARACTER"
    SUSPICIOUS_INSTRUCTION = "SUSPICIOUS_INSTRUCTION"


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    kind: FindingKind
    pattern: re.Pattern[str]
    keep_group: int | None = None  # group to keep verbatim before the redaction token (e.g. "password=")


def _rule(rule_id: str, kind: FindingKind, pattern: str, keep_group: int | None = None) -> _Rule:
    return _Rule(rule_id, kind, re.compile(pattern), keep_group)


SECRET_RULES = (
    _rule("private-key-block", FindingKind.SECRET,
          r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)"),
    _rule("aws-access-key-id", FindingKind.SECRET, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _rule("github-token", FindingKind.SECRET, r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    _rule("slack-token", FindingKind.SECRET, r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    _rule("api-secret-key", FindingKind.SECRET, r"\bsk-[A-Za-z0-9_-]{20,}"),
    _rule("jwt", FindingKind.SECRET, r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _rule("bearer-token", FindingKind.CREDENTIAL, r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/-]{16,}=*", keep_group=1),
    _rule("url-credentials", FindingKind.CREDENTIAL, r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+(?=@)",
          keep_group=1),
    _rule("credential-assignment", FindingKind.CREDENTIAL,
          r"(?i)(\b(?:[a-z0-9]+[_-])*(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
          r"refresh[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*)(?!\[REDACTED)"
          r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)", keep_group=1),
)
PII_RULES = (
    _rule("email", FindingKind.PII, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    _rule("phone-number", FindingKind.PII,
          r"(?<![\w.:/+-])(?:\+\d{1,3}[ .-]?)?\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}(?![\w.:/-])"),
)
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INSTRUCTION_RULES = (
    _rule("ignore-previous", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)\b(?:ignore|forget)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|your)\s+"
          r"(?:instructions|rules|prompts?|directions|guidance)"),
    _rule("disregard", FindingKind.SUSPICIOUS_INSTRUCTION, r"(?i)\bdisregard\b[^.\n]{0,80}"),
    _rule("action-directive", FindingKind.SUSPICIOUS_INSTRUCTION, r"(?i)\bEXECUTE_ACTION\s*:[^\n]{0,120}"),
    _rule("role-reassignment", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)\byou\s+(?:are\s+)?now\s+(?:have|are|an?|the)\b[^.\n]{0,80}"),
    _rule("privilege-claim", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)\b(?:grant|give)\s+(?:yourself|me|you)\b[^.\n]{0,80}"),
    _rule("authority-claim", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)\b(?:as\s+the\s+(?:administrator|admin|operator|system)|system\s+notice|"
          r"(?:analyst|admin|operator)\s+approved)\b[^.\n]{0,80}"),
    _rule("limit-override", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)\b(?:budget|limit|policy|permission|safety|guardrail)s?\s+(?:override|bypass|is\s+now)\b[^.\n]{0,80}"),
    _rule("override-controls", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)\b(?:override|bypass|disable)\s+(?:the\s+)?(?:policy|policies|safety|guardrails?|restrictions|"
          r"authori[sz]ation|permissions?|audit)"),
    _rule("prompt-markup", FindingKind.SUSPICIOUS_INSTRUCTION,
          r"(?i)</?\s*(?:system|assistant|instructions?)\s*>|\b(?:system|developer)\s+(?:prompt|message)\s*:"),
)
_INVISIBLE = {0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0x2060, 0xFEFF,
              *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
_SENSITIVE_KEY = re.compile(r"(?i)^(?:.*[_-])?(?:password|passwd|pwd|passphrase|secret|api[_-]?key|token|"
                            r"credentials?|private[_-]?key|authorization|cookie)$")


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


@dataclass
class _Tally:
    counts: dict[tuple[FindingKind, str, str], int] = field(default_factory=dict)

    def add(self, kind: FindingKind, rule_id: str, path: str, n: int = 1) -> None:
        if n:
            key = (kind, rule_id, path)
            self.counts[key] = self.counts.get(key, 0) + n


def _clean_controls(text: str, tally: _Tally | None, path: str) -> str:
    out, removed = [], 0
    for ch in text.replace("\r\n", "\n"):
        cp = ord(ch)
        if ch in "\n\t":
            out.append(ch)
        elif ch == "\r":
            out.append("\n")
        elif cp < 0x20 or 0x7F <= cp <= 0x9F or cp in _INVISIBLE or unicodedata.category(ch) == "Cs":
            removed += 1
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else "?")
        else:
            out.append(ch)
    if tally is not None:
        tally.add(FindingKind.CONTROL_CHARACTER, "control-or-invisible", path, removed)
    return "".join(out)


def _apply(rule: _Rule, text: str, tally: _Tally | None, path: str) -> str:
    def repl(m: re.Match[str]) -> str:
        if tally is not None:
            tally.add(rule.kind, rule.rule_id, path)
        kept = m.group(rule.keep_group) if rule.keep_group else ""
        return f"{kept}[REDACTED:{rule.rule_id}]"
    return rule.pattern.sub(repl, text)


def redact_text(text: str, tally: _Tally | None = None, path: str = "$", *, minimize_pii: bool = True,
                minimize_ip: bool = False) -> str:
    """Secret/credential redaction + control-character neutralisation (+ optional PII). Idempotent."""
    text = _clean_controls(text, tally, path)
    for rule in SECRET_RULES:
        text = _apply(rule, text, tally, path)
    if minimize_pii:
        def card(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn(digits):
                if tally is not None:
                    tally.add(FindingKind.PII, "payment-card", path)
                return "[REDACTED:payment-card]"
            return m.group(0)
        text = _CARD.sub(card, text)
        for rule in PII_RULES:
            text = _apply(rule, text, tally, path)
        if minimize_ip:
            text = _apply(_Rule("ipv4-address", FindingKind.PII, _IPV4), text, tally, path)
    return text


def audit_safe_text(text: str) -> str:
    """Normaliser for free text that is written into the audit ledger. Must stay idempotent."""
    return redact_text(text, minimize_pii=True)


def detect_instructions(text: str) -> list[tuple[str, int, int]]:
    """Spans of text that look like embedded instructions: (rule_id, start, end), non-overlapping."""
    spans: list[tuple[str, int, int]] = []
    for rule in INSTRUCTION_RULES:
        spans += [(rule.rule_id, m.start(), m.end()) for m in rule.pattern.finditer(text)]
    spans.sort(key=lambda s: (s[1], -s[2]))
    merged: list[tuple[str, int, int]] = []
    for span in spans:
        if merged and span[1] < merged[-1][2]:
            if span[2] > merged[-1][2]:
                merged[-1] = (merged[-1][0], merged[-1][1], span[2])
            continue
        merged.append(span)
    return merged


class SanitizationFinding(StrictModel):
    kind: FindingKind
    rule_id: Identifier
    path: ShortText
    count: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]


class SanitizedEvidenceView(StrictModel):
    """Derived, non-authoritative representation of one evidence item. Never a substitute for the original."""

    evidence_id: Identifier
    representation: Literal["SANITIZED_DERIVATIVE"] = "SANITIZED_DERIVATIVE"
    trust_level: Literal["UNTRUSTED_EVIDENCE"] = "UNTRUSTED_EVIDENCE"
    authoritative: Literal[False] = False
    original_integrity_digest: Sha256Hex          # copied from the original item, never recomputed here
    original_content_inline: bool
    sanitized_content: FrozenJson = None
    sanitized_content_digest: Sha256Hex
    content_modified: bool
    findings: tuple[SanitizationFinding, ...]
    contains_suspicious_instructions: bool
    sanitizer_version: ShortText

    @model_validator(mode="after")
    def _check(self) -> Self:
        if canonical_digest(self.sanitized_content) != self.sanitized_content_digest:
            raise ValueError("sanitized_content_digest does not match sanitized_content")
        suspicious = any(f.kind is FindingKind.SUSPICIOUS_INSTRUCTION for f in self.findings)
        if suspicious != self.contains_suspicious_instructions:
            raise ValueError("contains_suspicious_instructions disagrees with findings")
        return self

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.kind.value] = out.get(f.kind.value, 0) + f.count
        return out


@dataclass(frozen=True)
class Sanitizer:
    minimize_pii: bool = True
    minimize_ip: bool = False        # IPs are often investigation-relevant; opt in to remove them
    mark_instructions: bool = True
    max_depth: int = 32

    def _text(self, text: str, tally: _Tally, path: str) -> str:
        text = redact_text(text, tally, path, minimize_pii=self.minimize_pii, minimize_ip=self.minimize_ip)
        spans = detect_instructions(text)
        for rule_id, _, _ in spans:
            tally.add(FindingKind.SUSPICIOUS_INSTRUCTION, rule_id, path)
        if self.mark_instructions and spans:
            parts, last = [], 0
            for _, start, end in spans:
                parts += [text[last:start], UNTRUSTED_OPEN, text[start:end], UNTRUSTED_CLOSE]
                last = end
            text = "".join(parts) + text[last:]
        return text

    def _value(self, value: Any, tally: _Tally, path: str, depth: int) -> Any:
        if depth > self.max_depth:
            raise ValueError("content nested too deeply to sanitize")
        if isinstance(value, str):
            return self._text(value, tally, path)
        if isinstance(value, Mapping):
            out = {}
            for key, item in value.items():
                clean_key = _clean_controls(key, tally, f"{path}.<key>")
                child = f"{path}.{clean_key}"
                if _SENSITIVE_KEY.match(key) and item is not None and not isinstance(item, (Mapping, list, tuple)):
                    tally.add(FindingKind.CREDENTIAL, "sensitive-field-name", child)
                    out[clean_key] = "[REDACTED:sensitive-field-name]"
                else:
                    out[clean_key] = self._value(item, tally, child, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self._value(v, tally, f"{path}[{i}]", depth + 1) for i, v in enumerate(value)]
        return value

    def sanitize_value(self, value: Any) -> tuple[Any, tuple[SanitizationFinding, ...]]:
        """Sanitize plain JSON data; returns a NEW value. The input is not modified."""
        freeze_json(value)  # validates that this is JSON data (rejects models, bytes, ...)
        tally = _Tally()
        clean = self._value(value, tally, "$", 0)
        findings = tuple(SanitizationFinding(kind=k, rule_id=r, path=p[:256], count=n)
                         for (k, r, p), n in sorted(tally.counts.items(), key=lambda kv: (kv[0][2], kv[0][1])))
        return clean, findings

    def sanitize_item(self, item: EvidenceItem) -> SanitizedEvidenceView:
        if type(item) is not EvidenceItem:
            raise TypeError("only EvidenceItem instances can be sanitized; authority objects are never touched")
        subject = item.content if item.content is not None else item.content_reference
        clean, findings = self.sanitize_value(subject)
        return SanitizedEvidenceView(
            evidence_id=item.evidence_id, original_integrity_digest=item.integrity_digest,
            original_content_inline=item.content is not None, sanitized_content=clean,
            sanitized_content_digest=canonical_digest(clean),
            content_modified=canonical_digest(clean) != canonical_digest(subject), findings=findings,
            contains_suspicious_instructions=any(f.kind is FindingKind.SUSPICIOUS_INSTRUCTION for f in findings),
            sanitizer_version=SANITIZER_VERSION)
