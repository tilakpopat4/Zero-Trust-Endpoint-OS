#!/bin/bash
clear
echo "========================================"
echo "   Zero Trust OS — Starting Up"
echo "========================================"

echo "[1] Starting Docker services..."
sudo docker start keycloak > /dev/null 2>&1
cd ~/zerotrust/wazuh/wazuh-docker/single-node
sudo docker compose up -d > /dev/null 2>&1
sleep 5

echo "[2] Starting system services..."
sudo systemctl start wazuh-agent > /dev/null 2>&1
sudo systemctl start osqueryd > /dev/null 2>&1
sudo systemctl start auditd > /dev/null 2>&1
sudo systemctl start clamav-daemon > /dev/null 2>&1
sudo nft -f /etc/nftables-zerotrust.conf > /dev/null 2>&1

echo "[3] Adding honeypot watches..."
sudo auditctl -w /home/tilak/passwords.txt -p rwa -k zerotrust_honeypot > /dev/null 2>&1
sudo auditctl -w /home/tilak/bank_details.txt -p rwa -k zerotrust_honeypot > /dev/null 2>&1
sudo auditctl -w /home/tilak/secret_keys.txt -p rwa -k zerotrust_honeypot > /dev/null 2>&1

echo "[4] Stopping old processes..."
pkill -f master_notify.py > /dev/null 2>&1
pkill -f dashboard.py > /dev/null 2>&1
pkill -f login_monitor.py > /dev/null 2>&1
pkill opa > /dev/null 2>&1
sudo fuser -k 5000/tcp > /dev/null 2>&1
sleep 3

echo "[5] Starting OPA..."
cd ~/zerotrust/opa
nohup opa run --server policy.rego > /tmp/opa.log 2>&1 &
sleep 3

echo "[6] Starting Dashboard..."
cd ~/zerotrust
nohup python3 dashboard.py > /tmp/dashboard.log 2>&1 &
sleep 2

echo "[7] Starting Master Monitor..."
nohup python3 master_notify.py > /tmp/master.log 2>&1 &
sleep 8

echo "[8] Checking system status..."
echo ""
echo "========================================"
echo "   SYSTEM STATUS"
echo "========================================"

check_service() {
    if systemctl is-active --quiet $1 2>/dev/null; then
        echo "  ✅ $1"
    else
        echo "  ❌ $1"
    fi
}

check_process() {
    if pgrep -f "$1" > /dev/null 2>&1; then
        echo "  ✅ $2"
    else
        echo "  ❌ $2"
    fi
}

check_service auditd
check_service osqueryd
check_service clamav-daemon
check_service wazuh-agent
check_process "opa" "OPA Policy Engine"
check_process "dashboard.py" "Zero Trust Dashboard"
check_process "master_notify.py" "Master Monitor"

echo ""
echo "========================================"
echo "   ACCESS POINTS"
echo "========================================"
echo "  🌐 Dashboard   → http://localhost:5000"
echo "  🗺️  Threat Map  → http://localhost:5000/threat_map"
echo "  🔑 Keycloak    → http://localhost:8080"
echo "  📡 Wazuh       → https://localhost"
echo "  📋 OPA         → http://localhost:8181"
echo "========================================"
echo ""
echo "  Zero Trust OS is READY! 🔥"
echo "========================================"
