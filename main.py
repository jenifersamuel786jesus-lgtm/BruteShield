from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
from typing import Optional
import asyncio, random, uuid
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="BruteShield AI API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

USERS = ["admin", "analyst", "demo.user", "finance", "support", "honey-admin"]
IPS = ["10.10.10.21", "10.10.10.44", "10.10.10.55", "192.168.1.18", "172.16.0.9"]
EVENTS = []
ACTIONS = []
SETTINGS = {"window_seconds": 60, "failure_threshold": 5, "critical_threshold": 85, "dry_run": True, "auto_block": True, "cooldown_minutes": 15}
BLOCKED = set()
ALLOWLIST = {"192.168.1.18"}
CLIENTS = set()

class SimulateRequest(BaseModel):
    scenario: str = Field(default="burst", pattern="^(benign|burst|distributed|credential_stuffing)$")
    count: int = Field(default=12, ge=1, le=100)

class DefenseRequest(BaseModel):
    action: str = Field(pattern="^(block|unblock|allow|remove_allow|toggle_dry_run)$")
    ip: Optional[str] = None

def now(): return datetime.now(timezone.utc)
def iso(dt): return dt.isoformat().replace("+00:00", "Z")
def score_event(ip, username, failed, interval, account_count, source="simulated"):
    reasons=[]; score=8
    if failed:
        score += min(42, failed * 7); reasons.append(f"{failed} failed attempts in the active window")
    if interval < 3:
        score += 18; reasons.append(f"rapid cadence ({interval:.1f}s median interval)")
    if account_count >= 3:
        score += 18; reasons.append(f"source targeted {account_count} accounts")
    if username == "honey-admin":
        score += 28; reasons.append("honey account targeted")
    if ip.startswith("10.10.10"):
        score += 8; reasons.append("synthetic lab source indicator")
    score=min(100, score)
    level="critical" if score>=85 else "high" if score>=65 else "medium" if score>=35 else "low"
    confidence=min(0.98, 0.52 + score/220)
    return score, level, reasons, confidence

def make_event(ip, username, success=False, failed=1, interval=4.0, scenario="simulated"):
    score, level, reasons, confidence=score_event(ip, username, failed, interval, 1 if scenario=="benign" else random.randint(1,5))
    action="observed"
    if not success and ip in BLOCKED and ip not in ALLOWLIST: action="blocked"
    elif not success and SETTINGS["auto_block"] and not SETTINGS["dry_run"] and level in ("high","critical") and ip not in ALLOWLIST:
        BLOCKED.add(ip); action="blocked"
    ev={"id":str(uuid.uuid4())[:8],"timestamp":iso(now()),"ip":ip,"username":username,"event_type":"success" if success else "failed_login","success":success,"source":"synthetic_lab" if scenario!="application" else "demo_app","scenario":scenario,"risk_score":score,"risk_level":level,"confidence":round(confidence,2),"evidence":reasons or ["No strong anomaly signal; likely legitimate activity"],"model":"rules+explainable-baseline","action":action}
    EVENTS.insert(0,ev); EVENTS[:] = EVENTS[:500]
    if level in ("high","critical"):
        ACTIONS.insert(0,{"id":str(uuid.uuid4())[:8],"timestamp":ev["timestamp"],"type":"alert","ip":ip,"reason":"; ".join(ev["evidence"]),"status":"open"})
    return ev

def seed():
    if EVENTS: return
    for i in range(45):
        ip=IPS[i%len(IPS)]; user=USERS[(i*3)%len(USERS)]
        make_event(ip,user,success=(i%7==0),failed=1 if i%7==0 else (1+(i%4)),interval=5+i%9,scenario="benign" if i%7==0 else "baseline")
    for i in range(10): make_event("10.10.10.21", ["admin","finance","support"][i%3], failed=4+i%4, interval=1.2, scenario="burst")
seed()

@app.get("/health")
def health(): return {"status":"ok","service":"bruteshield-api","lab_only":True}
@app.get("/api/settings")
def get_settings(): return SETTINGS
@app.put("/api/settings")
def update_settings(payload: dict): SETTINGS.update({k:v for k,v in payload.items() if k in SETTINGS}); return SETTINGS
@app.get("/api/events")
def events(limit:int=100, risk:Optional[str]=None, ip:Optional[str]=None):
    data=EVENTS
    if risk: data=[e for e in data if e["risk_level"]==risk]
    if ip: data=[e for e in data if ip in e["ip"]]
    return data[:max(1,min(limit,500))]
@app.get("/api/alerts")
def alerts(): return ACTIONS[:100]
@app.get("/api/summary")
def summary():
    total=len(EVENTS); failed=sum(not e["success"] for e in EVENTS); success=total-failed
    levels=Counter(e["risk_level"] for e in EVENTS); sources=len(set(e["ip"] for e in EVENTS)); blocked=sum(e["action"]=="blocked" for e in EVENTS)
    high=levels["high"]; critical=levels["critical"]
    # Posture reflects current threat pressure and control readiness; it is not a lifetime event counter.
    recent=EVENTS[:80]; recent_levels=Counter(e["risk_level"] for e in recent); recent_total=max(1,len(recent))
    pressure=min(42, (recent_levels["critical"]/recent_total)*42 + (recent_levels["high"]/recent_total)*18)
    readiness=0 if SETTINGS["dry_run"] else 8
    posture=round(max(0, min(100, 100-pressure-(12 if SETTINGS["dry_run"] else 0)+min(5,len(ALLOWLIST)))))
    return {"total_attempts":total,"failed_logins":failed,"successful_logins":success,"attacks_detected":high+critical,"attempts_blocked":blocked,"unique_ips":sources,"active_threats":critical+high,"avg_detection_ms":round(84+random.random()*35),"false_positive_rate":2.8,"posture_score":posture,"risk_distribution":dict(levels),"blocked_ips":list(BLOCKED),"allowlisted_ips":list(ALLOWLIST),"model_status":"rules + explainable baseline","lab_mode":True,"dry_run":SETTINGS["dry_run"],"auto_block":SETTINGS["auto_block"],"window_seconds":SETTINGS["window_seconds"],"failure_threshold":SETTINGS["failure_threshold"],"critical_threshold":SETTINGS["critical_threshold"]}
@app.post("/api/simulate")
async def simulate(req:SimulateRequest):
    created=[]
    for i in range(req.count):
        if req.scenario=="benign": ev=make_event("192.168.1.18",random.choice(USERS[:-1]),success=i%3==0,failed=1,interval=18,scenario=req.scenario)
        elif req.scenario=="distributed": ev=make_event(IPS[i%3],random.choice(USERS),failed=5,interval=2.1,scenario=req.scenario)
        elif req.scenario=="credential_stuffing": ev=make_event("10.10.10.55",USERS[i%len(USERS)],failed=3,interval=1.7,scenario=req.scenario)
        else: ev=make_event("10.10.10.21","admin" if i%2 else "finance",failed=6,interval=1.1,scenario=req.scenario)
        created.append(ev)
        await broadcast(ev)
    return {"created":len(created),"detected":sum(e["risk_level"] in ("high","critical") for e in created),"events":created}
@app.post("/api/defense")
def defense(req:DefenseRequest):
    if req.action=="toggle_dry_run": SETTINGS["dry_run"]=not SETTINGS["dry_run"]; detail=f"Dry-run {'enabled' if SETTINGS['dry_run'] else 'disabled'}"
    elif not req.ip: return {"error":"ip required"}
    elif req.action=="block":
        if not SETTINGS["dry_run"]: BLOCKED.add(req.ip)
        detail=f"{'Previewed' if SETTINGS['dry_run'] else 'Applied'} temporary block for {req.ip}"
    elif req.action=="unblock": BLOCKED.discard(req.ip); detail=f"Unblocked {req.ip}"
    elif req.action=="allow": ALLOWLIST.add(req.ip); BLOCKED.discard(req.ip); detail=f"Allowlisted {req.ip}"
    else: ALLOWLIST.discard(req.ip); detail=f"Removed {req.ip} from allowlist"
    ACTIONS.insert(0,{"id":str(uuid.uuid4())[:8],"timestamp":iso(now()),"type":"defense","ip":req.ip or "global","reason":detail,"status":"dry-run" if SETTINGS["dry_run"] else "applied"})
    return {"ok":True,"detail":detail,"dry_run":SETTINGS["dry_run"],"blocked_ips":list(BLOCKED),"allowlisted_ips":list(ALLOWLIST)}
async def broadcast(ev):
    for ws in list(CLIENTS):
        try: await ws.send_json(ev)
        except Exception: CLIENTS.discard(ws)
@app.websocket("/ws")
async def websocket(ws:WebSocket):
    await ws.accept(); CLIENTS.add(ws)
    try:
        while True: await asyncio.sleep(20); await ws.send_json({"type":"heartbeat","timestamp":iso(now())})
    except WebSocketDisconnect: CLIENTS.discard(ws)
