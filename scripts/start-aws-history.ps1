param(
    [string]$Database = (Join-Path $env:LOCALAPPDATA 'IdentityGuard/aws-history.sqlite'),
    [int]$Port = 8010
)

$ErrorActionPreference = 'Stop'
$Database = [IO.Path]::GetFullPath($Database)
$secure = Read-Host 'Choose a private workspace token with at least 32 characters' -AsSecureString
$token = [System.Net.NetworkCredential]::new('', $secure).Password
if ($token.Length -lt 32) { throw 'The token must have at least 32 characters.' }

Push-Location (Join-Path $PSScriptRoot '..')
try {
    $env:PYTHONPATH = 'backend'
    $env:IG_SOURCE = 'aws'
    $env:IG_DATABASE = $Database
    $env:IG_WORKSPACE_TOKEN = $token
    if (-not (Test-Path 'frontend/dist/index.html' -PathType Leaf)) {
        throw 'Build the console with npm --prefix frontend ci and npm --prefix frontend run build first.'
    }
    Write-Host "Open http://127.0.0.1:$Port/integrations/aws and enter the workspace token."
    python -m uv run --locked python -m uvicorn --factory app.api:from_env --host 127.0.0.1 --port $Port --no-access-log
} finally {
    Remove-Item Env:IG_WORKSPACE_TOKEN,Env:IG_SOURCE,Env:IG_DATABASE -ErrorAction SilentlyContinue
    Remove-Variable token,secure
    Pop-Location
}
