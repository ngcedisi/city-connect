@echo off
call venv\Scripts\activate
set ADMIN_KEY=change-me-to-something-secret
set DEV_MODE=1
python app.py
