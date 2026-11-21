param(
    [string]$Database = 'data/demo.sqlite',
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    python -m uv sync --locked
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    npm --prefix frontend ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    npm --prefix frontend run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $env:PYTHONPATH = 'backend'
    $env:IG_SOURCE = 'demo'
    $env:IG_DATABASE = $Database
    Remove-Item Env:IG_WORKSPACE_TOKEN -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Database)) {
        python -m uv run --locked python -m app.devdata seed --database $Database
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    python -m uv run --locked python -m uvicorn --factory app.api:from_env --host 127.0.0.1 --port $Port --no-access-log
} finally {
    Pop-Location
}
