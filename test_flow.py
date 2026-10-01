"""Run while the server is running (DEV_MODE=1):  python test_flow.py"""
import requests
B = "http://127.0.0.1:5000"; ADMIN = {"X-Admin-Key": "change-me-to-something-secret"}
def otp(p): return requests.post(B+"/otp/send", json={"phone": p}).json()["dev_code"]
def book(p, n, d, t=1, email=""):
    r = requests.post(B+"/book", json={"phone": p, "name": n, "device_id": d, "trip_id": t, "seats": 1, "otp": otp(p), "email": email})
    return r.status_code, r.json().get("status") or r.json().get("error")
print("1 normal           :", book("0690465294", "Thabo", "dev-A"))
print("2 duplicate        :", book("0690465294", "Thabo", "dev-A"))
print("3 device mismatch 1:", book("0711111111", "Fake One", "dev-A"))
print("4 device mismatch 2:", book("0722222222", "Fake Two", "dev-A"))
print("5 blocked          :", book("0690465294", "Thabo", "dev-A"))
print("6 IP spam (one IP, 7 phones):")
for i in range(7): print("   ", i+1, book(f"07600000{i:02d}", f"Person {i}", f"dev-{i}", t=2))
print("7 review queue     :", [(b["id"], b["risk"]) for b in requests.get(B+"/admin/bookings", headers=ADMIN).json() if b["status"] == "review"])
