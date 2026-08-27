@echo off
REM Runs fencrypt using this project's virtual environment, so you don't have to
REM activate it first. %~dp0 is this .bat file's own folder, which means the
REM launcher works no matter which directory you call it from.
"%~dp0.venv\Scripts\python.exe" "%~dp0fencrypt.py" %*
