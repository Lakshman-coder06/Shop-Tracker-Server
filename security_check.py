"""
tests/security_check.py
------------------------
Self-check for the shop server's security rules. Run it against a BRAND-NEW
test server (it uses the starter accounts Worker 1/Worker 2/Admin with their
starter PINs and saves a couple of test jobs - never run it on your real shop
data):

    python server.py                      (in one window, with a fresh/empty data folder)
    python tests/security_check.py http://localhost:8000
"""
import requests, json, sys
B = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
def login(n,p):
    r = requests.post(B+"/api/login", json={"name":n,"pin":p}); return r
def rpc(tok, fn, *a, **k):
    r = requests.post(B+"/api/rpc", json={"fn":fn,"args":list(a),"kwargs":k}, headers={"Authorization":"Bearer "+tok} if tok else {})
    return r
ok = True
def check(label, cond, extra=""):
    global ok
    print(("PASS " if cond else "FAIL ") + label, extra if not cond else "")
    ok &= bool(cond)

r = login("Worker 1","1111"); check("worker1 login", r.status_code==200)
j = r.json(); w1 = j["token"]
check("pin_hash NOT sent in login response", "pin_hash" not in j["user"], j["user"])
check("fresh install forces PIN change", j["user"]["must_change_pin"] == 1)
w2 = login("Worker 2","2222").json()["token"]
ad = login("Admin","9999").json()["token"]
check("wrong PIN -> 401", login("Worker 1","0000").status_code==401)
check("unknown name -> same 401", login("Nobody","0000").status_code==401)

# no token / bad token
check("rpc without token -> 401", rpc(None,"get_active_services").status_code==401)
check("rpc with forged token -> 401", rpc("abc.def","get_active_services").status_code==401)

services = rpc(w1,"get_active_services").json()["result"]
check("services list works", len(services)>0 and isinstance(services[0], dict))
sid = services[0]["id"]

# W1 creates a job; W2 creates a job; try to spoof worker_id
r = rpc(w1,"create_transaction", worker_id=999, service_id=sid, quantity=2, payment_method="Cash", status="Completed")
check("create_transaction ok", r.status_code==200 and r.json()["ok"], r.text)
code1 = r.json()["result"]
r = rpc(w2,"create_transaction", worker_id=1, service_id=sid, quantity=3, payment_method="UPI", status="Pending", advance_amount=10)
check("W2 create_transaction (tries to spoof worker_id=1)", r.status_code==200, r.text)

# W1 tries to see everyone's by passing worker_id=None
rows = rpc(w1,"get_transactions", date_filter="today", worker_id=None).json()["result"]
names = {x["worker_name"] for x in rows}
check("W1 asking for ALL still only sees own jobs", names=={"Worker 1"}, names)
rows2 = rpc(w2,"get_transactions", date_filter="today", worker_id=1).json()["result"]
check("W2 asking for worker 1's jobs only sees own", {x["worker_name"] for x in rows2}=={"Worker 2"}, rows2)
check("spoofed worker_id was ignored (job saved under real caller)", all(x["worker_id"]==1 for x in rows))
rows3 = rpc(ad,"get_transactions", date_filter="today", worker_id=None).json()["result"]
check("Admin sees BOTH workers' jobs", {x["worker_name"] for x in rows3}=={"Worker 1","Worker 2"}, {x["worker_name"] for x in rows3})
summ = rpc(ad,"get_today_summary", worker_id=None).json()["result"]
check("Admin shop-wide summary counts 2 jobs", summ["jobs"]==2, summ)
s1 = rpc(w1,"get_today_summary", worker_id=None).json()["result"]
check("W1 summary(None) is scoped to own (1 job)", s1["jobs"]==1, s1)

# ownership
tid2 = [x for x in rows3 if x["worker_name"]=="Worker 2"][0]["id"]
r = rpc(w1,"record_payment", tid2, 5, "Cash", 1)
check("W1 cannot take payment on W2's job (403)", r.status_code==403, r.text)
r = rpc(w1,"cancel_transaction", tid2, "x", 1)
check("W1 cannot cancel W2's job (403)", r.status_code==403, r.text)
r = rpc(ad,"record_payment", tid2, 5, "Cash", 1)
check("Admin can record payment on any job", r.status_code==200 and r.json()["ok"], r.text)
au = rpc(ad,"get_audit_logs").json()["result"]

# admin-only
for fn,args in [("get_all_workers_admin",[]),("get_audit_logs",[]),("get_all_services_admin",[]),("get_worker_performance_today",[])]:
    check(f"worker blocked from {fn} (403)", rpc(w1,fn,*args).status_code==403)
check("worker cannot change a rate (403)", rpc(w1,"update_service_rate", sid, 1, 1).status_code==403)
check("worker cannot create worker (403)", rpc(w1,"create_worker","X","1234","admin").status_code==403)
r = rpc(ad,"get_all_workers_admin").json()["result"]
check("admin worker list has no pin_hash", all("pin_hash" not in u for u in r))

# validation
check("negative quantity rejected (400)", rpc(w1,"create_transaction", worker_id=1, service_id=sid, quantity=-5, payment_method="Cash", status="Completed").status_code==400)
check("bad payment method rejected (400)", rpc(w1,"create_transaction", worker_id=1, service_id=sid, quantity=1, payment_method="Bitcoin", status="Completed").status_code==400)
check("rate param not accepted (400)", rpc(w1,"create_transaction", worker_id=1, service_id=sid, quantity=1, payment_method="Cash", status="Completed", rate=1).status_code==400)
check("unknown/legacy fn blocked (404)", rpc(w1,"mark_transaction_paid", 1, 1).status_code==404)
check("internal fn blocked (404)", rpc(w1,"get_connection").status_code==404)

# audit identity cannot be spoofed
r = rpc(w1,"mark_transaction_completed", 1, 4)  # claims to be user 4 (admin)
logs = rpc(ad,"get_audit_logs").json()["result"]
print("   audit sample:", [(l["field_changed"], l["changed_by_name"]) for l in logs[:3]])

# duplicate service -> typed error
r = rpc(ad,"create_service","Xerox B&W",5,0)
print("   duplicate service response:", r.status_code, r.json())

print("\nALL PASSED" if ok else "\nSOME FAILED")
