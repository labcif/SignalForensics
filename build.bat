@echo off
setlocal enabledelayedexpansion

:: Criar a pasta temporária build
if exist build rmdir /s /q build
mkdir build

:: Copiar apenas os ficheiros e pastas necessários
xcopy /E /I /Y modules build\modules
xcopy /E /I /Y templates build\templates
copy /Y decrypt_signal.py build\

:: Criar o arquivo .pyz com zipapp
python -m zipapp build -o decrypt_signal.pyz -m "decrypt_signal:main"

:: Remover a pasta temporária
rmdir /s /q build

:: Mensagem de sucesso
echo.
echo [OK] decrypt_signal.pyz created successfully!
echo Execute with: python decrypt_signal.pyz
echo.

endlocal
