@echo off
setlocal
chcp 65001 >nul
title Lulz 1.0.1 - Web Security Toolkit
color 0A
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 goto try_py
python -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 goto try_py
python "%~dp0lulz.py" %*
goto done
:try_py
where py >nul 2>nul
if errorlevel 1 goto missing
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 goto missing
py -3 "%~dp0lulz.py" %*
goto done
:missing
echo Python 3.11+ is required. Install Python from https://www.python.org/downloads/
pause
exit /b 1
:done
if errorlevel 1 pause
endlocal
