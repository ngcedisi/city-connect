"""Creates the Vapi assistant. Usage (Command Prompt):
   set VAPI_API_KEY=your-vapi-private-key
   set SERVER_URL=https://coach-bot.onrender.com
   set VAPI_SECRET=the-secret-from-render
   python create_vapi_assistant.py"""
import os, json, requests
raw = open("vapi_assistant.json", encoding="utf-8").read()
raw = raw.replace("SERVER_URL", os.environ["SERVER_URL"].rstrip("/")).replace('"VAPI_SECRET"', json.dumps(os.environ["VAPI_SECRET"]))
r = requests.post("https://api.vapi.ai/assistant", data=raw,
                  headers={"Authorization": "Bearer " + os.environ["VAPI_API_KEY"], "Content-Type": "application/json"})
print(r.status_code, r.text)
