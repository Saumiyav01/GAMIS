param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GamisArguments
)

$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$envFile = Join-Path $backend ".env"

if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        $text = $line.Trim()
        if ($text.Length -eq 0 -or $text.StartsWith("#")) {
            continue
        }
        $separator = $text.IndexOf("=")
        if ($separator -le 0) {
            continue
        }
        $name = $text.Substring(0, $separator).Trim()
        $value = $text.Substring($separator + 1).Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
            ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$pythonCommand = if (Test-Path $venvPython) { $venvPython } else { "python" }
Push-Location $backend
try {
    & $pythonCommand -m gamis @GamisArguments
    $result = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $result
