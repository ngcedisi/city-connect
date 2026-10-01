COACH BOT - Flask backend + Vapi voice + Render hosting
(Windows Command Prompt)

A) TEST ON YOUR PC
   1. Install Python 3.10+ (tick "Add Python to PATH"). Open Command Prompt in this folder.
   2. setup.bat      then      run.bat
   3. 2nd Command Prompt:  venv\Scripts\activate  &  pip install requests  &  python test_flow.py

B) PUT ON RENDER
   1. Install Git. In this folder run:
        git init
        git add .
        git commit -m "first version"
      Create an empty repo on github.com, then:
        git remote add origin https://github.com/YOURNAME/coach-bot.git
        git push -u origin master
   2. render.com > New > Blueprint > pick the repo > Apply.
      Render reads render.yaml and creates the service, disk and secrets.
   3. Render > coach-bot > Environment: copy ADMIN_KEY and VAPI_SECRET.
   4. Your URL looks like https://coach-bot.onrender.com  (open /trips to check)

C) CONNECT VAPI
   1. vapi.com > Dashboard > API Keys > copy your PRIVATE key.
   2. In Command Prompt (venv active, requests installed):
        set VAPI_API_KEY=your-private-key
        set SERVER_URL=https://coach-bot.onrender.com
        set VAPI_SECRET=value-from-render
        python create_vapi_assistant.py
   3. Vapi dashboard > Assistants > Coach Booking Assistant: pick a voice and
      transcriber language, then Phone Numbers > attach a number to it.
      (If the script errors, create the assistant in the dashboard and paste the
       prompt and 3 tools from vapi_assistant.json.)

STAFF DASHBOARD
- Open your Render URL (https://coach-bot.onrender.com/) and sign in with ADMIN_KEY.
- Pages: Dashboard, Bookings, Passengers, Buses & Routes, AI Calls, Lost Luggage, Fraud Protection, Analytics, Settings.
- WhatsApp and Payment show 'Not connected' until you build those parts.

SECURITY (merged from your city-to-city-ai-automation upload)
- Risk score per booking: same IP 3+ attempts = +25, 5+ = +70, duplicate (same phone, name and trip) = +80,
  repeat attempts on same phone and trip = +30, unknown IP = +5.
- Score 60+ = held for STAFF REVIEW (Fraud Protection page, Approve or Reject). 80+ = blocked for a while.
- IP is a signal only. It is never blocked automatically. Voice calls skip IP rules.
- Voice and web both go through the same check, so the Vapi agent cannot skip it.
- Admin key checked in constant time. 10 wrong keys = that IP locked out for 15 minutes.
- Production start refuses to run with a default ADMIN_KEY or no VAPI_SECRET.
- OTP codes are never printed when DEV_MODE=0. Phones are masked in staff alerts.
- TRUST_PROXY_HOPS=1 (set in render.yaml): the real client IP is read from the last proxy hop only.
  After deploying, check Fraud Protection shows real customer IPs, not Render's. If not, ask me to adjust the hop count.
- All of these can now be changed live on the dashboard Settings page (env vars below are only the starting defaults).
- Tunable in Render > Environment: BOOKING_RATE_WINDOW_MINUTES, MAX_BOOKING_ATTEMPTS,
  DUPLICATE_WINDOW_MINUTES, STAFF_REVIEW_THRESHOLD, RISK_BLOCK_THRESHOLD.

NOTES
- Render free plan: no persistent disk, data is lost on restart. Use the paid plan in render.yaml.
- send_otp_message() and alert_staff() in app.py only print for now. Connect a WhatsApp/SMS provider.
- Voice: the caller's number is used as phone and device. IP rules are skipped for voice.
- Payment: call /pay/confirm (header X-Admin-Key) from your PayFast/Ozow notification.
