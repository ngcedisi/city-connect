"""Coach booking backend with anti-fake-booking protection.
Run: python app.py   (see README.txt)"""
import os, sqlite3, random, time, hmac
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
PROXY_HOPS = int(os.environ.get("TRUST_PROXY_HOPS", "0"))   # 1 on Render: trust only the last proxy hop
if PROXY_HOPS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=PROXY_HOPS)
DB = os.environ.get("DB_PATH", "coach.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "change-me")
DEV_MODE = os.environ.get("DEV_MODE", "1") == "1"   # 1 = show OTP in response (testing only)
# Editable in the dashboard (Settings page). Env vars only set the starting defaults.
_e = lambda k, d: type(d)(os.environ.get(k, d))
SETTINGS = [
 # key, label, help, group, default, min, max
 ("bookings_enabled", "Accept new bookings", "Turn off to pause all web, WhatsApp and phone bookings.", "Booking rules", 1, 0, 1),
 ("hold_minutes", "Seat hold time (minutes)", "How long a seat is held before payment.", "Booking rules", _e("HOLD_MINUTES", 15), 5, 60),
 ("strike_hold_minutes", "Hold after a device strike (minutes)", "Shorter hold when one device uses different details.", "Booking rules", 3, 1, 15),
 ("review_hold_minutes", "Staff review hold (minutes)", "How long a seat waits for staff to approve.", "Booking rules", 30, 5, 120),
 ("busy_deposit_pct", "Deposit on busy routes (%)", "Share of the fare paid up front on busy trips.", "Booking rules", 50, 10, 100),
 ("max_unpaid_phone_device", "Unpaid holds per phone or device per day", "More than this is refused.", "Fraud protection", 3, 1, 10),
 ("max_unpaid_ip", "Unpaid holds per IP per day", "Higher, because many real users share one mobile IP.", "Fraud protection", 10, 3, 50),
 ("review_threshold", "Send to staff review at risk score", "Risk 0 to 100.", "Fraud protection", _e("STAFF_REVIEW_THRESHOLD", 60), 10, 99),
 ("block_threshold", "Block for a while at risk score", "Must be higher than the review score.", "Fraud protection", _e("RISK_BLOCK_THRESHOLD", 80), 20, 100),
 ("risk_window_minutes", "Attempt window (minutes)", "How far back repeated attempts are counted.", "Fraud protection", _e("BOOKING_RATE_WINDOW_MINUTES", 15), 5, 120),
 ("max_ip_attempts", "Attempts per IP before high risk", "Same IP, within the attempt window.", "Fraud protection", _e("MAX_BOOKING_ATTEMPTS", 5), 3, 30),
 ("duplicate_window_minutes", "Duplicate window (minutes)", "Same phone, name and trip within this time is a duplicate.", "Fraud protection", _e("DUPLICATE_WINDOW_MINUTES", 30), 5, 240),
 ("support_phone", "Support phone number", "Read out to customers who are blocked.", "Contact", "", 0, 20),
 ("staff_alert_phone", "Staff alert WhatsApp number", "Where fraud alerts are sent once WhatsApp is connected.", "Contact", "", 0, 20),
]
SDEF = {k: d for k, _, _, _, d, _, _ in SETTINGS}

def now(): return datetime.utcnow()
def iso(d): return d.strftime("%Y-%m-%d %H:%M:%S")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()

def S(key):
    d = SDEF[key]
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    try: return type(d)(row[0]) if row else d
    except ValueError: return d

def office():
    p = S("support_phone")
    return f"Contact our office on {p}." if p else "Contact our office."

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS trips(id INTEGER PRIMARY KEY, route TEXT, depart TEXT,
        seats_total INTEGER, price REAL, busy INTEGER DEFAULT 0, bus TEXT DEFAULT '', status TEXT DEFAULT 'On time');
    CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY, trip_id INTEGER, seats INTEGER,
        name TEXT, phone TEXT, device TEXT, ip TEXT, status TEXT, amount_due REAL,
        created TEXT, expires TEXT, email TEXT DEFAULT '', risk INTEGER DEFAULT 0, reasons TEXT DEFAULT '');
    CREATE TABLE IF NOT EXISTS otps(phone TEXT, code TEXT, expires TEXT, tries INTEGER DEFAULT 0, used INTEGER DEFAULT 0, created TEXT);
    CREATE TABLE IF NOT EXISTS blocklist(id INTEGER PRIMARY KEY, kind TEXT, value TEXT, reason TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS strikes(device TEXT PRIMARY KEY, count INTEGER);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS calls(id INTEGER PRIMARY KEY, ts TEXT, caller TEXT, intent TEXT, status TEXT);
    CREATE TABLE IF NOT EXISTS luggage(id INTEGER PRIMARY KEY, ref TEXT, name TEXT, phone TEXT, route TEXT,
        description TEXT, status TEXT DEFAULT 'Open', created TEXT);
    CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, ts TEXT, phone TEXT, device TEXT, ip TEXT, result TEXT, trip_id INTEGER);
    """)
    for tbl, col in (("trips", "bus TEXT DEFAULT ''"), ("trips", "status TEXT DEFAULT 'On time'"), ("bookings", "email TEXT DEFAULT ''"),
                     ("bookings", "risk INTEGER DEFAULT 0"), ("bookings", "reasons TEXT DEFAULT ''"), ("attempts", "trip_id INTEGER")):
        try: c.execute(f"ALTER TABLE {tbl} ADD COLUMN " + col)
        except sqlite3.OperationalError: pass
    if c.execute("SELECT COUNT(*) FROM trips").fetchone()[0] == 0:
        d0 = now().replace(hour=0, minute=0, second=0)
        c.executemany("INSERT INTO trips(route,depart,seats_total,price,busy,bus,status) VALUES(?,?,?,?,?,?,?)", [
            ("Johannesburg → Durban", iso(d0 + timedelta(hours=6)), 65, 350, 0, "CT101", "On time"),
            ("Johannesburg → Cape Town", iso(d0 + timedelta(hours=6)), 65, 750, 1, "CT205", "On time"),
            ("Johannesburg → Pretoria", iso(d0 + timedelta(hours=8, minutes=30)), 65, 120, 0, "CT118", "Delayed (20m)"),
            ("Johannesburg → Bloemfontein", iso(d0 + timedelta(hours=10)), 65, 320, 0, "CT132", "On time"),
            ("Johannesburg → East London", iso(d0 + timedelta(hours=12)), 65, 650, 1, "CT167", "On time")])
    c.commit(); c.close()

def mask(v):
    v = str(v or "")
    return "***" if len(v) <= 4 else f"{v[:2]}***{v[-2:]}"

RATE = {}
def rate_limited(bucket, key, n, secs):
    t = time.time(); k = (bucket, key)
    RATE[k] = [x for x in RATE.get(k, []) if t - x < secs]
    if len(RATE[k]) >= n: return True
    RATE[k].append(t); return False

def alert_staff(msg):
    to = S("staff_alert_phone")
    line = f"[{iso(now())}] ALERT{(' -> ' + mask(to)) if to else ''}: {msg}"
    print(line)
    open("alerts.log", "a", encoding="utf-8").write(line + "\n")
    # TODO: send to staff WhatsApp here (WhatsApp Business API / Twilio)

def send_otp_message(phone, code):
    if DEV_MODE: print(f"OTP for {phone}: {code}")  # never print codes in production
    # TODO: send via WhatsApp Business API / SMS provider here

def release_expired():
    db().execute("UPDATE bookings SET status='expired' WHERE status IN ('held','review') AND expires < ?", (iso(now()),))
    db().commit()

def log_attempt(phone, device, ip, result, trip_id=None):
    db().execute("INSERT INTO attempts(ts,phone,device,ip,result,trip_id) VALUES(?,?,?,?,?,?)",
                 (iso(now()), phone, device, ip, result, trip_id)); db().commit()

def is_blocked(phone, device, ip):
    r = db().execute("SELECT 1 FROM blocklist WHERE (kind='phone' AND value=?) OR (kind='device' AND value=?) OR (kind='ip' AND value=?)",
                     (phone, device, ip)).fetchone()
    return r is not None

def block(kind, value, reason):
    if value and not db().execute("SELECT 1 FROM blocklist WHERE kind=? AND value=?", (kind, value)).fetchone():
        db().execute("INSERT INTO blocklist(kind,value,reason,created) VALUES(?,?,?,?)", (kind, value, reason, iso(now())))
        db().commit()

def client_ip():
    # X-Forwarded-For is only trusted through ProxyFix (TRUST_PROXY_HOPS); it can be spoofed otherwise.
    return request.remote_addr or "unknown"

def need_admin():
    """True = reject. Constant-time key check, locks an IP out after 10 wrong keys in 15 minutes."""
    ip = client_ip(); t = time.time()
    fails = [x for x in RATE.get(("adminfail", ip), []) if t - x < 900]
    RATE[("adminfail", ip)] = fails
    if len(fails) >= 10: return True
    ok = hmac.compare_digest(request.headers.get("X-Admin-Key", "").encode(), ADMIN_KEY.encode())
    if not ok: fails.append(t)
    return not ok

@app.after_request
def secure_headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Cache-Control"] = "no-store"
    if request.path in ("/", "/dashboard"):
        r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                                "font-src https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'")
    return r

def seats_taken(trip_id):
    return db().execute("SELECT COALESCE(SUM(seats),0) FROM bookings WHERE trip_id=? AND status IN ('held','paid','review')",
                        (trip_id,)).fetchone()[0]

# ---------- public ----------
@app.get("/trips")
def trips():
    release_expired()
    out = []
    for t in db().execute("SELECT * FROM trips"):
        d = dict(t); d["seats_left"] = t["seats_total"] - seats_taken(t["id"]); out.append(d)
    return jsonify(out)

@app.post("/otp/send")
def otp_send():
    phone = (request.json or {}).get("phone", "").strip()
    if not phone: return jsonify(error="phone required"), 400
    if rate_limited("otp-ip", client_ip(), 30, 600): return jsonify(error="Too many requests. Try again later."), 429
    recent = db().execute("SELECT COUNT(*) FROM otps WHERE phone=? AND created > ?",
                          (phone, iso(now() - timedelta(minutes=10)))).fetchone()[0]
    if recent >= 3: return jsonify(error="Too many codes requested. Try again in 10 minutes."), 429
    code = f"{random.randint(0, 999999):06d}"
    db().execute("INSERT INTO otps(phone,code,expires,created) VALUES(?,?,?,?)",
                 (phone, code, iso(now() + timedelta(minutes=5)), iso(now()))); db().commit()
    send_otp_message(phone, code)
    resp = {"sent": True}
    if DEV_MODE: resp["dev_code"] = code
    return jsonify(resp)

def check_otp(phone, code):
    row = db().execute("SELECT rowid,* FROM otps WHERE phone=? AND used=0 ORDER BY rowid DESC LIMIT 1", (phone,)).fetchone()
    if not row or row["expires"] < iso(now()) or row["tries"] >= 5: return False
    if row["code"] != str(code):
        db().execute("UPDATE otps SET tries=tries+1 WHERE rowid=?", (row["rowid"],)); db().commit(); return False
    db().execute("UPDATE otps SET used=1 WHERE rowid=?", (row["rowid"],)); db().commit(); return True

def risk_score(phone, name, email, trip_id, ip, web):
    """Additive risk score (0-100). IP is one signal, never an automatic ban."""
    risk, why = 0, []
    since = lambda m: iso(now() - timedelta(minutes=m))
    if web and ip and ip != "unknown":
        n = db().execute("SELECT COUNT(*) FROM attempts WHERE ip=? AND ts>?", (ip, since(S("risk_window_minutes")))).fetchone()[0]
        if n >= S("max_ip_attempts"): risk += 70; why.append("Too many recent booking attempts from the same IP")
        elif n >= 3: risk += 25; why.append("Several recent booking attempts from the same IP")
    elif web:
        risk += 5; why.append("Client IP could not be identified")
    dup = db().execute("SELECT 1 FROM bookings WHERE trip_id=? AND status IN ('held','paid','review') AND created>? AND "
                       "(phone=? AND name=? OR (?!='' AND email=?))", (trip_id, since(S("duplicate_window_minutes")), phone, name, email, email)).fetchone()
    if dup: risk += 80; why.append("Possible duplicate booking for the same passenger and trip")
    same = db().execute("SELECT COUNT(*) FROM attempts WHERE phone=? AND trip_id=? AND ts>?", (phone, trip_id, since(S("risk_window_minutes")))).fetchone()[0]
    if same >= 2: risk += 30; why.append("Repeated booking attempts for the same phone and trip")
    return min(risk, 100), why

def do_booking(phone, name, device, ip, trip_id, seats, otp, web=True, email=""):
    """Shared booking logic for web/WhatsApp (web=True) and Vapi voice calls (web=False).
    Voice calls: IP checks are skipped (every call comes from Vapi's servers) and
    different names on one phone number are allowed (families booking for others)."""
    release_expired()
    name = name.strip().lower(); email = (email or "").strip().lower()
    if not (phone and name and device and trip_id) or not 1 <= seats <= 6:
        return {"error": "phone, name, device_id, trip_id and seats (1-6) required"}, 400
    if not S("bookings_enabled"):
        return {"error": f"Bookings are paused right now. {office()}"}, 503
    if is_blocked(phone, device, ip if web else ""):
        log_attempt(phone, device, ip, "blocked", trip_id); return {"error": f"Booking not available. {office()}"}, 403
    if not check_otp(phone, otp):
        log_attempt(phone, device, ip, "bad_otp", trip_id); return {"error": "Invalid or expired OTP"}, 401

    day_ago = iso(now() - timedelta(days=1))
    def unpaid(col, val):
        return db().execute(f"SELECT COUNT(*) FROM bookings WHERE {col}=? AND status!='paid' AND created>?", (val, day_ago)).fetchone()[0]
    if unpaid("phone", phone) >= S("max_unpaid_phone_device") or unpaid("device", device) >= S("max_unpaid_phone_device") or (web and unpaid("ip", ip) >= S("max_unpaid_ip")):
        log_attempt(phone, device, ip, "limit", trip_id); return {"error": "Too many unpaid bookings today. Pay for an existing one first."}, 429

    risk, why = risk_score(phone, name, email, trip_id, ip, web)
    if risk >= S("block_threshold"):
        log_attempt(phone, device, ip, "risk_blocked", trip_id)
        alert_staff(f"Temporarily blocked (risk {risk}) phone={mask(phone)}: " + "; ".join(why))
        return {"error": f"Booking not available right now. {office()}"}, 429

    prev = db().execute("SELECT DISTINCT name, phone FROM bookings WHERE device=? AND created>?", (device, day_ago)).fetchall()
    mismatch = any((p["phone"] != phone) or (web and p["name"] != name) for p in prev)
    hold = S("hold_minutes"); instant_pay = False
    if mismatch:
        s_ = db().execute("SELECT count FROM strikes WHERE device=?", (device,)).fetchone()
        count = (s_["count"] if s_ else 0) + 1
        db().execute("INSERT INTO strikes(device,count) VALUES(?,?) ON CONFLICT(device) DO UPDATE SET count=?", (device, count, count)); db().commit()
        if count >= 2:
            for k, v in (("device", device), ("phone", phone)):  # IP not auto-blocked: shared mobile IPs would block real customers
                block(k, v, "repeat device mismatch")
            alert_staff(f"BLOCKED device={mask(device)} phone={mask(phone)} (repeat mismatch). IP seen: {ip} (not blocked, review manually)")
            log_attempt(phone, device, ip, "auto_blocked", trip_id)
            return {"error": f"Booking not available. {office()}"}, 403
        alert_staff(f"Strike 1: device {mask(device)} used with different details (phone={mask(phone)})")
        hold, instant_pay = S("strike_hold_minutes"), True
        risk = max(risk, S("review_threshold")); why.append("Same device used with different details")

    trip = db().execute("SELECT * FROM trips WHERE id=?", (trip_id,)).fetchone()
    if not trip: return {"error": "Trip not found"}, 404
    if trip["seats_total"] - seats_taken(trip_id) < seats: return {"error": "Not enough seats"}, 409

    review = risk >= S("review_threshold")
    total = trip["price"] * seats
    due = total if instant_pay else (total * (S("busy_deposit_pct") / 100) if trip["busy"] else total)
    status = "review" if review else "held"
    if review: hold = S("review_hold_minutes")
    cur = db().execute("INSERT INTO bookings(trip_id,seats,name,phone,device,ip,status,amount_due,created,expires,email,risk,reasons) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (trip_id, seats, name, phone, device, ip, status, due, iso(now()), iso(now() + timedelta(minutes=hold)), email, risk, "; ".join(why)))
    db().commit(); log_attempt(phone, device, ip, "review" if review else "held", trip_id)
    if review:
        alert_staff(f"Booking {cur.lastrowid} needs staff review (risk {risk}): " + "; ".join(why))
        return {"booking_id": cur.lastrowid, "status": "review", "pay_within_minutes": None, "amount_due": due,
                "note": "Staff must verify this booking before payment. We will contact you shortly."}, 200
    return {"booking_id": cur.lastrowid, "status": "held", "pay_within_minutes": hold, "amount_due": due,
            "note": "Extra verification: pay now to keep your seat." if instant_pay else
                    ("Deposit required on busy route." if trip["busy"] else "Pay to confirm.")}, 200

@app.post("/book")
def book():
    j = request.json or {}
    out, code = do_booking(j.get("phone", "").strip(), j.get("name", ""), j.get("device_id", "").strip(), client_ip(),
                           j.get("trip_id"), int(j.get("seats", 1)), j.get("otp", ""), web=True, email=j.get("email", ""))
    return jsonify(out), code

# ---------- Vapi voice webhook ----------
VAPI_SECRET = os.environ.get("VAPI_SECRET", "")

def make_otp(phone):
    recent = db().execute("SELECT COUNT(*) FROM otps WHERE phone=? AND created > ?",
                          (phone, iso(now() - timedelta(minutes=10)))).fetchone()[0]
    if recent >= 3: return None
    code = f"{random.randint(0, 999999):06d}"
    db().execute("INSERT INTO otps(phone,code,expires,created) VALUES(?,?,?,?)",
                 (phone, code, iso(now() + timedelta(minutes=5)), iso(now()))); db().commit()
    send_otp_message(phone, code)
    return code

def run_voice_tool(name, args, caller):
    release_expired()
    if name == "get_trips":
        rows = []
        for t in db().execute("SELECT * FROM trips"):
            left = t["seats_total"] - seats_taken(t["id"])
            rows.append(f"Trip {t['id']}: {t['route']}, departs {t['depart']}, R{t['price']:.0f} per seat, {left} seats left")
        return ". ".join(rows)
    if not caller:
        return "I could not see your phone number, so please call from the number you want to book with."
    if name == "send_otp":
        code = make_otp(caller)
        return "Too many codes requested. Ask the caller to try again in 10 minutes." if code is None else \
               "A 6 digit code was sent to the caller by message. Ask them to read it out."
    if name == "book_seat":
        out, status = do_booking(caller, args.get("name", ""), "voice:" + caller, "vapi", args.get("trip_id"),
                                 int(args.get("seats", 1)), str(args.get("otp", "")).replace(" ", ""), web=False)
        if status != 200: return out["error"]
        if out["status"] == "review": return "The booking needs staff verification first. Tell the caller staff will call back shortly. Do not take payment."
        return (f"Booking {out['booking_id']} is held. Pay R{out['amount_due']:.0f} within {out['pay_within_minutes']} minutes "
                f"or the seat is released. {out['note']}")
    if name == "create_luggage_case":
        n = db().execute("SELECT COUNT(*) FROM luggage").fetchone()[0] + 1
        ref = f"CC-{now().year}-{1000 + n}"
        db().execute("INSERT INTO luggage(ref,name,phone,route,description,created) VALUES(?,?,?,?,?,?)",
                     (ref, args.get("name", ""), caller, args.get("route", ""), args.get("description", ""), iso(now())))
        db().commit()
        return f"Lost luggage case {ref} created. Tell the caller staff will call back on this number."
    return "Unknown tool."

@app.post("/vapi/webhook")
def vapi_webhook():
    if VAPI_SECRET and request.headers.get("X-Vapi-Secret") != VAPI_SECRET:
        return jsonify(error="unauthorized"), 401
    msg = (request.json or {}).get("message", {})
    if msg.get("type") != "tool-calls":
        return jsonify(ok=True)
    caller = (msg.get("call", {}).get("customer", {}) or {}).get("number", "")
    results = []
    for tc in msg.get("toolCallList", []):
        fn = tc.get("function", {})
        args = fn.get("arguments", tc.get("arguments", {})) or {}
        if isinstance(args, str):
            import json as _j
            try: args = _j.loads(args)
            except Exception: args = {}
        try:
            text = run_voice_tool(fn.get("name", tc.get("name", "")), args, caller)
        except Exception as e:
            print("voice tool error:", e); text = "Sorry, something went wrong. Offer to transfer to a human agent."
        tname = fn.get("name", tc.get("name", ""))
        intent = {"get_trips": "Trip info", "book_seat": "Booking", "create_luggage_case": "Luggage claim"}.get(tname)
        if intent:
            db().execute("INSERT INTO calls(ts,caller,intent,status) VALUES(?,?,?,?)", (iso(now()), caller, intent,
                         "Blocked (fraud)" if "not available" in str(text).lower() else "Completed")); db().commit()
        results.append({"toolCallId": tc.get("id"), "result": " ".join(str(text).split())})  # single line
    return jsonify(results=results)

@app.post("/pay/confirm")
def pay_confirm():
    """Call this from your payment webhook (PayFast/Ozow). Admin key required."""
    if need_admin(): return jsonify(error="unauthorized"), 401
    release_expired()
    b = db().execute("SELECT * FROM bookings WHERE id=?", ((request.json or {}).get("booking_id"),)).fetchone()
    if not b: return jsonify(error="not found"), 404
    if b["status"] != "held": return jsonify(error=f"booking is {b['status']}"), 409
    db().execute("UPDATE bookings SET status='paid' WHERE id=?", (b["id"],)); db().commit()
    return jsonify(status="paid")

# ---------- dashboard ----------
from flask import send_from_directory
@app.get("/")
@app.get("/dashboard")
def dashboard():
    return send_from_directory("static", "index.html")

def day_count(sql, d0, d1, *extra):
    return db().execute(sql, (iso(d0), iso(d1)) + extra).fetchone()[0] or 0

@app.get("/admin/stats")
def admin_stats():
    if need_admin(): return jsonify(error="unauthorized"), 401
    release_expired()
    t0 = now().replace(hour=0, minute=0, second=0); y0 = t0 - timedelta(days=1); t1 = t0 + timedelta(days=1)
    def pair(sql, *extra):
        a, b = day_count(sql, t0, t1, *extra), day_count(sql, y0, t0, *extra)
        return {"today": a, "pct": None if not b else round((a - b) * 100 / b)}
    q = lambda col, tbl, cond="": f"SELECT {col} FROM {tbl} WHERE ts>=? AND ts<?{cond}"
    outcomes = {r[0]: r[1] for r in db().execute("SELECT status, COUNT(*) FROM calls GROUP BY status")}
    return jsonify(
        calls=pair("SELECT COUNT(*) FROM calls WHERE ts>=? AND ts<?"),
        bookings=pair("SELECT COUNT(*) FROM bookings WHERE created>=? AND created<?"),
        passengers=pair("SELECT SUM(seats) FROM bookings WHERE created>=? AND created<? AND status!='expired'"),
        fraud=pair("SELECT COUNT(*) FROM attempts WHERE ts>=? AND ts<? AND result IN ('blocked','auto_blocked','limit','risk_blocked','review')"),
        revenue=day_count("SELECT SUM(amount_due) FROM bookings WHERE created>=? AND created<? AND status='paid'", t0, t1),
        on_hold=day_count("SELECT SUM(amount_due) FROM bookings WHERE created>=? AND created<? AND status='held'", t0, t1),
        total_calls=db().execute("SELECT COUNT(*) FROM calls").fetchone()[0],
        total_bookings=db().execute("SELECT COUNT(*) FROM bookings").fetchone()[0],
        outcomes=outcomes,
        services={"vapi": bool(VAPI_SECRET), "whatsapp": bool(os.environ.get("WHATSAPP_TOKEN")),
                  "payments": bool(os.environ.get("PAYMENT_KEY"))})

@app.get("/admin/trips")
def admin_trips():
    if need_admin(): return jsonify(error="unauthorized"), 401
    release_expired()
    out = []
    for t in db().execute("SELECT * FROM trips ORDER BY depart"):
        d = dict(t); d["taken"] = seats_taken(t["id"]); out.append(d)
    return jsonify(out)

@app.post("/admin/trip_status")
def admin_trip_status():
    if need_admin(): return jsonify(error="unauthorized"), 401
    j = request.json or {}
    db().execute("UPDATE trips SET status=? WHERE id=?", (j.get("status", "On time"), j.get("id"))); db().commit()
    return jsonify(ok=True)

@app.get("/admin/calls")
def admin_calls():
    if need_admin(): return jsonify(error="unauthorized"), 401
    return jsonify([dict(r) for r in db().execute("SELECT * FROM calls ORDER BY id DESC LIMIT 100")])

@app.get("/admin/luggage")
def admin_luggage():
    if need_admin(): return jsonify(error="unauthorized"), 401
    return jsonify([dict(r) for r in db().execute("SELECT * FROM luggage ORDER BY id DESC LIMIT 100")])

@app.post("/admin/luggage/update")
def admin_luggage_update():
    if need_admin(): return jsonify(error="unauthorized"), 401
    j = request.json or {}
    db().execute("UPDATE luggage SET status=? WHERE id=?", (j.get("status", "Open"), j.get("id"))); db().commit()
    return jsonify(ok=True)

# ---------- settings ----------
@app.get("/admin/settings")
def admin_settings():
    if need_admin(): return jsonify(error="unauthorized"), 401
    meta = [dict(key=k, label=l, help=h, group=g, default=d, min=mn, max=mx, kind="text" if isinstance(d, str) else "number") for k, l, h, g, d, mn, mx in SETTINGS]
    return jsonify(meta=meta, values={k: S(k) for k in SDEF})

@app.post("/admin/settings")
def admin_settings_save():
    if need_admin(): return jsonify(error="unauthorized"), 401
    vals, errs = (request.json or {}).get("values", {}), []
    clean = {}
    for k, l, h, g, d, mn, mx in SETTINGS:
        if k not in vals: continue
        try:
            v = str(vals[k]).strip()[:20] if isinstance(d, str) else int(float(vals[k]))
        except (ValueError, TypeError):
            errs.append(f"{l}: enter a number"); continue
        if isinstance(d, str):
            if v and not v.replace("+", "").replace(" ", "").isdigit(): errs.append(f"{l}: digits only")
        elif not mn <= v <= mx: errs.append(f"{l}: use {mn} to {mx}")
        clean[k] = v
    if int(clean.get("review_threshold", S("review_threshold"))) >= int(clean.get("block_threshold", S("block_threshold"))):
        errs.append("Review score must be lower than the block score")
    if errs: return jsonify(error=". ".join(errs)), 400
    for k, v in clean.items():
        db().execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=?", (k, str(v), str(v)))
    db().commit()
    return jsonify(ok=True, values={k: S(k) for k in SDEF})

@app.post("/admin/settings/reset")
def admin_settings_reset():
    if need_admin(): return jsonify(error="unauthorized"), 401
    db().execute("DELETE FROM settings"); db().commit()
    return jsonify(ok=True, values={k: S(k) for k in SDEF})

# ---------- admin ----------
@app.get("/admin/bookings")
def admin_bookings():
    if need_admin(): return jsonify(error="unauthorized"), 401
    release_expired()
    return jsonify([dict(r) for r in db().execute("SELECT b.*, t.route FROM bookings b LEFT JOIN trips t ON t.id=b.trip_id ORDER BY b.id DESC LIMIT 200")])

@app.post("/admin/review")
def admin_review():
    """Staff decision on a booking in review: action = approve | reject."""
    if need_admin(): return jsonify(error="unauthorized"), 401
    j = request.json or {}
    b = db().execute("SELECT * FROM bookings WHERE id=? AND status='review'", (j.get("booking_id"),)).fetchone()
    if not b: return jsonify(error="not in review"), 404
    if j.get("action") == "approve":
        db().execute("UPDATE bookings SET status='held', expires=? WHERE id=?", (iso(now() + timedelta(minutes=S("hold_minutes"))), b["id"]))
    else:
        db().execute("UPDATE bookings SET status='expired' WHERE id=?", (b["id"],))
    db().commit(); return jsonify(ok=True)

@app.get("/admin/blocklist")
def admin_blocklist():
    if need_admin(): return jsonify(error="unauthorized"), 401
    return jsonify([dict(r) for r in db().execute("SELECT * FROM blocklist")])

@app.post("/admin/block")
def admin_block():
    if need_admin(): return jsonify(error="unauthorized"), 401
    j = request.json or {}; block(j["kind"], j["value"], j.get("reason", "manual")); return jsonify(ok=True)

@app.post("/admin/unblock")
def admin_unblock():
    if need_admin(): return jsonify(error="unauthorized"), 401
    j = request.json or {}
    db().execute("DELETE FROM blocklist WHERE kind=? AND value=?", (j["kind"], j["value"]))
    if j["kind"] == "device": db().execute("DELETE FROM strikes WHERE device=?", (j["value"],))
    db().commit(); return jsonify(ok=True)

@app.get("/admin/attempts")
def admin_attempts():
    if need_admin(): return jsonify(error="unauthorized"), 401
    return jsonify([dict(r) for r in db().execute("SELECT * FROM attempts ORDER BY id DESC LIMIT 200")])

if not DEV_MODE and (ADMIN_KEY in ("", "change-me") or not VAPI_SECRET):
    raise SystemExit("Set a real ADMIN_KEY and VAPI_SECRET before running with DEV_MODE=0.")
init_db()  # also runs under gunicorn on Render

import os
port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)
