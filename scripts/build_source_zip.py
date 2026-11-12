"""Build the single GAMIS V4 P0-P7 dashboard archive, with a manifest, and verify the result.

Usage (from repo root): python scripts/build_source_zip.py [output.zip]
Writes MANIFEST.json (path, size, sha256 of every included file) into the repo root, zips the complete
project under a top-level GAMIS/ folder, then re-opens the archive and checks it against the manifest.
The default archive name is GAMIS_CONNECTED_DASHBOARD.zip.
"""
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "MANIFEST.json"
EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "env", "node_modules", "dist", "build",
                 "htmlcov", ".mypy_cache", ".ruff_cache", "dev-keys", ".idea", ".vscode"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pem", ".key", ".p12", ".pfx", ".tmp", ".swp", ".log", ".zip", ".db",
                     ".sqlite", ".sqlite3", ".db-journal", ".db-wal", ".db-shm"}
EXCLUDED_NAMES = {".env", ".coverage", ".DS_Store", "Thumbs.db", MANIFEST}
SECRET_PATTERN = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE " + rb"KEY-----")
REQUIRED = ["README.md", "backend/pyproject.toml", "backend/requirements.txt", "backend/gamis/__init__.py",
            "backend/gamis/tools/mock_tools.py", "backend/gamis/evaluation/harness.py", "backend/seeds/logs.json",
            "backend/gamis/schemas/mission.py", "backend/gamis/schemas/assignment.py",
            "backend/gamis/schemas/evidence.py", "backend/gamis/schemas/tools.py",
            "backend/gamis/security/canonical.py", "backend/gamis/security/signing.py",
            "backend/gamis/security/keys.py", "backend/gamis/authority/service.py",
            "backend/gamis/authority/verification.py", "backend/gamis/tools/registry.py",
            "backend/tests/unit/test_harness.py", "backend/tests/unit/test_p1_schemas.py",
            "backend/tests/security/test_p1_crypto.py", "backend/tests/unit/test_p1_authority.py",
            "backend/tests/unit/test_p1_registry.py", "backend/tests/integration/test_p1_p0_integration.py",
            "scripts/verify_p1.py", "scripts/build_source_zip.py", MANIFEST,
            "backend/gamis/__main__.py", "backend/gamis/cli.py", "backend/gamis/audit/events.py",
            "backend/gamis/audit/ledger.py", "backend/gamis/audit/checkpoints.py", "backend/gamis/audit/recorder.py",
            "backend/gamis/evidence/store.py", "backend/gamis/evidence/content_store.py",
            "backend/gamis/evidence/sanitize.py", "backend/gamis/storage/sqlite.py",
            "backend/gamis/security/trust_io.py", "backend/gamis/authority/grants.py", "backend/tests/p2_support.py",
            "backend/tests/unit/test_p2_audit_ledger.py", "backend/tests/unit/test_p2_evidence_store.py",
            "backend/tests/unit/test_p2_sanitize.py", "backend/tests/security/test_p2_checkpoints.py",
            "backend/tests/failure/test_p2_recovery.py", "backend/tests/integration/test_p2_cli.py",
            "backend/tests/integration/test_p2_integration.py", "scripts/verify_p2.py",
            "backend/gamis/gateway/__init__.py", "backend/gamis/gateway/approval.py",
            "backend/gamis/llm/provider.py", "backend/gamis/runtime.py",
            "backend/gamis/agents/models.py", "backend/gamis/agents/supervisor.py",
            "backend/gamis/agents/workers.py", "backend/gamis/agents/orchestrator.py",
            "backend/gamis/agents/intelligence.py", "backend/gamis/agents/intelligence_models.py",
            "backend/tests/integration/test_p4_p5_local.py", "backend/tests/unit/test_ollama_provider.py",
            "backend/tests/integration/test_p6_p7_recovery.py",
            "docs/IMPLEMENTATION_STATUS.md",
            "backend/.env.example",
            "backend/requirements.txt", "scripts/run.ps1", "gamis_dashboard.html",
            "backend/app/__init__.py", "backend/app/main.py", "backend/app/api.py",
            "backend/app/schemas.py", "docs/API.md", "backend/tests/integration/test_api_dashboard.py",
            "scripts/start-api.ps1"]


def included(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if set(rel.parts[:-1]) & EXCLUDED_DIRS or any(p.endswith(".egg-info") for p in rel.parts):
        return False
    if path.name in EXCLUDED_NAMES or path.suffix in EXCLUDED_SUFFIXES:
        return False
    return not (path.name.endswith(".env") and path.name != ".env.example")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    output = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT.parent / "GAMIS_CONNECTED_DASHBOARD.zip"
    files = sorted(p for p in ROOT.rglob("*") if p.is_file() and included(p))
    for path in files:
        if SECRET_PATTERN.search(path.read_bytes()):
            print(f"REFUSING: possible private key in {path.relative_to(ROOT)}")
            return 1
    entries = [{"path": p.relative_to(ROOT).as_posix(), "size": p.stat().st_size, "sha256": sha256(p.read_bytes())}
               for p in files]
    manifest = {"archive": output.name, "root_folder": ROOT.name, "phase": "P0-P7", "file_count": len(entries),
                "note": "MANIFEST.json itself is in the archive but not listed.", "files": entries}
    (ROOT / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in [*files, ROOT / MANIFEST]:
            zf.write(path, f"{ROOT.name}/{path.relative_to(ROOT).as_posix()}")

    # --- verification -------------------------------------------------------------------------
    problems = []
    with zipfile.ZipFile(output) as zf:
        if zf.testzip() is not None:
            problems.append("archive failed CRC check")
        names = {n[len(ROOT.name) + 1:] for n in zf.namelist()}
        listed = json.loads(zf.read(f"{ROOT.name}/{MANIFEST}"))
        expected = {e["path"] for e in listed["files"]}
        if names - {MANIFEST} != expected:
            problems.append(f"manifest/archive mismatch: {sorted((names - {MANIFEST}) ^ expected)}")
        for entry in listed["files"]:
            data = zf.read(f"{ROOT.name}/{entry['path']}")
            if sha256(data) != entry["sha256"] or len(data) != entry["size"]:
                problems.append(f"content mismatch: {entry['path']}")
        problems += [f"missing expected file: {r}" for r in REQUIRED if r not in names]
        bad = [n for n in names if "__pycache__" in n or n.endswith((".pyc", ".pem", ".key", ".db")) or "/.git/" in f"/{n}"
               or n.split("/")[-1] == ".env"]
        problems += [f"excluded content present: {n}" for n in bad]
    for problem in problems:
        print("PROBLEM:", problem)
    print(f"{output}  ({output.stat().st_size} bytes, {len(names)} files incl. manifest)")
    print("ARCHIVE VERIFIED" if not problems else "ARCHIVE VERIFICATION FAILED")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
