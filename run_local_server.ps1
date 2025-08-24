Write-Host "Setting up PDF License Server for local testing..." -ForegroundColor Green

# Required environment variables
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="admin123"
$env:FLASK_ENV="development"

# Optional variables (GitHub integration disabled for local testing)
# $env:GITHUB_TOKEN="your_github_token_here"
# $env:GITHUB_REPO="your_username/your_repo"
# $env:GITHUB_BRANCH="main"

# Database will use SQLite locally (no DATABASE_URL needed)

Write-Host ""
Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "ADMIN_USERNAME=$env:ADMIN_USERNAME"
Write-Host "ADMIN_PASSWORD=***"
Write-Host "FLASK_ENV=$env:FLASK_ENV"
Write-Host ""
Write-Host "Starting server on http://localhost:5000" -ForegroundColor Cyan
Write-Host "Admin panel: http://localhost:5000/admin" -ForegroundColor Cyan
Write-Host "Username: $env:ADMIN_USERNAME" -ForegroundColor Green
Write-Host "Password: $env:ADMIN_PASSWORD" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

python server.py
