@echo off
echo Setting up PDF License Server for local testing...

REM Required environment variables
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=admin123
set FLASK_ENV=development

REM Optional variables (GitHub integration disabled for local testing)
REM set GITHUB_TOKEN=your_github_token_here
REM set GITHUB_REPO=your_username/your_repo
REM set GITHUB_BRANCH=main

REM Database will use SQLite locally (no DATABASE_URL needed)

echo.
echo Environment variables set:
echo ADMIN_USERNAME=%ADMIN_USERNAME%
echo ADMIN_PASSWORD=***
echo FLASK_ENV=%FLASK_ENV%
echo.
echo Starting server on http://localhost:5000
echo Admin panel: http://localhost:5000/admin
echo Username: %ADMIN_USERNAME%
echo Password: %ADMIN_PASSWORD%
echo.
echo Press Ctrl+C to stop the server
echo.

python server.py
