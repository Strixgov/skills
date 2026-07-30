@echo off
setlocal
rem strix-verify — Windows entry point for the bundled @strixgov/verifier.
rem Mirrors bin/strix-verify (the POSIX entry point) exactly: same resolution
rem order, same env vars, same exit-code passthrough. Windows cannot execute a
rem shebang'd sh script directly, so this .cmd is the real launcher on this
rem platform; keep the two in sync if the resolution logic ever changes.
set "PLUGIN_ROOT=%~dp0.."
set "VENDORED=%PLUGIN_ROOT%\vendor\strixgov-verifier\bin\verify.mjs"
if not defined STRIX_VERIFIER_VERSION set "STRIX_VERIFIER_VERSION=1.11.0"

if "%STRIX_VERIFIER_FORCE_NPX%"=="1" goto :usenpx
if exist "%VENDORED%" (
  node "%VENDORED%" %*
  exit /b %ERRORLEVEL%
)

:usenpx
call npx -y "@strixgov/verifier@%STRIX_VERIFIER_VERSION%" %*
exit /b %ERRORLEVEL%
