# NetWatch Enterprise Production Deployment Guide

**Target Platforms:** Windows Server 2019/2022 / Windows 11 & Linux (Ubuntu 22.04 LTS / RHEL 9 / Debian 12)  
**Architecture:** FastAPI (Python) + React / Vite (TypeScript) + SQLite / PostgreSQL  

---

## 1. System Requirements & Prerequisites

### Minimum Server Hardware Specifications
- **CPU:** 4 vCPUs (x86_64 / AMD64)
- **RAM:** 8 GB RAM minimum (16 GB recommended for heavy Syslog volumes)
- **Storage:** 50 GB SSD storage (High IOPS for telemetry log writes)
- **Network Interface:** 1 Gbps / 10 Gbps Ethernet

### Required Software Packages
- **Python:** Version 3.10, 3.11, 3.12, 3.13, or 3.14
- **Node.js & npm:** Node.js >= 18.0.0, npm >= 9.0.0
- **Git:** Version >= 2.30
- **Operating System Privileges:** Administrator on Windows / `root` or `sudo` on Linux (required for Syslog Port 514 binding and OS firewall/process controls)

---

## 2. Linux Production Deployment (Ubuntu 22.04 LTS / Debian 12)

### Step 1: Clone Repository & Setup Virtual Environment
```bash
cd /opt
sudo git clone https://github.com/koppineeedi/NetWatch-Network-Security-Monitoring-Suspicious-Activity-Detection-Platform.git netwatch
cd netwatch

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install backend dependencies
pip install --upgrade pip
pip install -r backend/requirements.txt
```

### Step 2: Configure Environment Variables
```bash
cp .env.example .env
nano .env
```
Ensure the following variables are properly configured in `.env`:
```env
DATABASE_URL=postgresql://netwatch_user:SecurePass123!@localhost:5432/netwatch_db
NETWATCH_SECRET_KEY=e8f9a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0
NETWATCH_CORS_ORIGINS=https://soc.netwatch.local,https://192.168.1.100
NETWATCH_SOAR_DRY_RUN=false
```

### Step 3: Seed Admin Account & Database Tables
```bash
python -m backend.app.scripts.create_admin
python backend/app/scripts/config_check.py
```

### Step 4: Build Frontend Assets
```bash
cd frontend
npm install
npm run build
cd ..
```

### Step 5: Configure Linux Systemd Service for Backend
Create `/etc/systemd/system/netwatch-backend.service`:
```ini
[Unit]
Description=NetWatch Defensive SIEM & SOAR Backend Engine
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netwatch
ExecStart=/opt/netwatch/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5
EnvironmentFile=/opt/netwatch/.env

# Grant capability to bind UDP 514 Syslog without full root shell
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable netwatch-backend
sudo systemctl start netwatch-backend
sudo systemctl status netwatch-backend
```

### Step 6: Configure Nginx Reverse Proxy & TLS (HTTPS/WSS)
Create `/etc/nginx/sites-available/netwatch`:
```nginx
server {
    listen 80;
    server_name soc.netwatch.local;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.netwatch.local;

    ssl_certificate /etc/ssl/certs/netwatch.crt;
    ssl_certificate_key /etc/ssl/private/netwatch.key;

    # Static Frontend Assets
    location / {
        root /opt/netwatch/frontend/dist;
        try_files $uri $uri/ /index.html;
    }

    # Backend API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket Real-Time Proxy
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```
Enable site and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/netwatch /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 3. Windows Production Deployment (Windows Server / Windows 11)

### Step 1: Run Windows PowerShell as Administrator
Open PowerShell as **Administrator**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

### Step 2: Install Dependencies & Setup Environment
```powershell
cd C:\Users\HP\OneDrive\Desktop\net

# Create Python Virtual Environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r backend\requirements.txt

# Configure environment variables
Copy-Item .env.example .env
```

### Step 3: Build Frontend Production Bundle
```powershell
cd frontend
npm install
npx vite build
cd ..
```

### Step 4: Validate Production Configuration
```powershell
python backend\app\scripts\config_check.py
```

### Step 5: Start Backend Server via NSSM Service or Process
```powershell
# Manual background launch (for staging/testing)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
```

To run NetWatch as a native Windows Service, use [NSSM (Non-Sucking Service Manager)](https://nssm.cc/):
```powershell
nssm install NetWatchBackend "C:\Users\HP\OneDrive\Desktop\net\venv\Scripts\uvicorn.exe" "app.main:app --host 0.0.0.0 --port 8000"
nssm set NetWatchBackend AppDirectory "C:\Users\HP\OneDrive\Desktop\net"
nssm start NetWatchBackend
```

---

## 4. Port & Firewall Requirements

| Port | Protocol | Usage | Inbound/Outbound |
| :--- | :--- | :--- | :--- |
| `80` | TCP | HTTP Web Server Redirect | Inbound |
| `443` | TCP | HTTPS Web Dashboard & WSS WebSockets | Inbound |
| `8000` | TCP | FastAPI REST API Backend | Internal Localhost |
| `514` | UDP / TCP | Remote Network Syslog Ingestion | Inbound |
| `5432` | TCP | PostgreSQL Database Server | Internal / DB Server |

---

## 5. Post-Deployment Verification

Verify operational health:
```bash
curl http://localhost:8000/health
# Output: {"status": "HEALTHY", ...}

curl http://localhost:8000/ready
# Output: {"status": "READY", ...}

curl http://localhost:8000/api/system/status
# Output: {"status": "OPERATIONAL", ...}
```
