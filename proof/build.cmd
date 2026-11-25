@echo off
setlocal
if not "%GITHUB_ACTIONS%"=="true" exit /b 90
if not "%RUNNER_OS%"=="Windows" exit /b 91
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.44
if errorlevel 1 exit /b %errorlevel%
"%RUNNER_TOOL_CACHE%\Python\3.12.10\x64\python.exe" -I -B "%GITHUB_WORKSPACE%\proof\build_candidate.py"
exit /b %errorlevel%
