@echo off
setlocal enabledelayedexpansion

:: Create temporary build folder
if exist build rmdir /s /q build
mkdir build

:: Copy the necessary files
xcopy /E /I /Y modules build\modules
xcopy /E /I /Y templates build\templates
copy /Y decrypt_signal.py build\

:: Create the .pyz archive
python -m zipapp build -o decrypt_signal.pyz -m "decrypt_signal:main"

:: Delete temporary folder
rmdir /s /q build

:: Success message
echo.
echo [OK] decrypt_signal.pyz created successfully!
echo Execute with: python decrypt_signal.pyz
echo.

endlocal
