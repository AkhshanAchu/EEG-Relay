@echo off
python "%~dp0egi_live.py" %*
if errorlevel 1 pause
