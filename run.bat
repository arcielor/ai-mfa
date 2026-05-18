@echo off
echo ================================================
echo   SecureAuth - AI/ML Enhanced MFA System
echo   Computer Security Project Demo
echo ================================================
echo.
echo [1/2] Installing dependencies...
pip install -r requirements.txt --quiet
echo.
echo [2/2] Starting Flask server...
echo.
echo  Open your browser at: http://127.0.0.1:5000
echo  Press CTRL+C to stop the server.
echo.
python app.py
pause
