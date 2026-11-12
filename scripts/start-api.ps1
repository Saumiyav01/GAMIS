param(
    [string]$ApiHost = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$Reload
)

$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root "backend\.env"
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$pythonCommand = if (Test-Path $venvPython) { $venvPython } else { "python" }

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

$arguments = @("-m", "uvicorn", "app.main:app", "--app-dir", "backend",
               "--host", $ApiHost, "--port", "$Port")
if ($Reload) {
    $arguments += "--reload"
}

Push-Location $root
try {
    & $pythonCommand @arguments
    $result = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $result
