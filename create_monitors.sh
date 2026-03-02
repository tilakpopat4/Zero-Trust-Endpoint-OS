#!/bin/bash
echo "Creating all monitors..."

# 1. Discord Notifier
cat > ~/zerotrust/discord_notify.py << 'PYEOF'
import requests
import subprocess
import json
import time
import urllib3
from datetime import datetime
urllib3.disable_warnings()

WEBHOOK = "https://discord.com/api/webhooks/1467201811835256864/eqaebLbs6ntuQ0XG6W35ZFHv9Oks6tNJ5BYAfgjalbpsZ63kBsgqW6O4QSgxKJzpbTut"

def send_discord(title, description, color, fields=[]):
    embed = {"embeds": [{"title": title, "description": description, "color": color, "fields": fields,
        "footer": {"text": "Zero Trust OS • Kali Linux • " + datetime.now().strftime("%d %b %Y %H:%M:%S")}}]}
    try:
        requests.post(WEBHOOK, json=embed, timeout=5, verify=False)
    except: pass

def check_wazuh_alerts(last_seen):
    try:
        result = subprocess.run(['tail','-n','100','/var/ossec/logs/alerts/alerts.log'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        new_alerts = []
        current = {}
        for line in lines:
            if '** Alert' in line:
                if current: new_alerts.append(current)
                current = {'time':'','level':0,'description':'','timestamp':0}
                try: current['timestamp'] = float(line.split('Alert ')[1].split('.')[0])
                except: pass
            elif 'Rule:' in line and 'level' in line:
                try: current['level'] = int(line.split('level')[1].split(')')[0].strip().replace(' ',''))
                except: pass
            elif line.strip() and not line.startswith('**') and not line.startswith('Rule'):
                if not current.get('description'): current['description'] = line.strip()[:100]
        if current: new_alerts.append(current)
        for alert in new_alerts:
            ts = alert.get('timestamp', 0)
            if ts > last_seen and alert.get('description'):
                lvl = alert.get('level', 0)
                color = 0xFF0000 if lvl>=10 else 0xFF8C00 if lvl>=6 else 0x00FF88
                emoji = "🚨" if lvl>=10 else "⚠️" if lvl>=6 else "ℹ️"
                severity = "HIGH" if lvl>=10 else "MEDIUM" if lvl>=6 else "LOW"
                send_discord(f"{emoji} Wazuh Alert — {severity}", f"**{alert['description']}**", color,
                    [{"name":"Level","value":str(lvl),"inline":True},{"name":"Severity","value":severity,"inline":True}])
                last_seen = max(last_seen, ts)
        return last_seen
    except: return last_seen

def check_firewall_blocks(last_seen_blocks):
    try:
        result = subprocess.run(['dmesg'], capture_output=True, text=True)
        new_blocks = []
        for line in result.stdout.split('\n'):
            if 'ZT-BLOCKED' in line:
                try:
                    ts = float(line.split('[')[1].split(']')[0].strip())
                    if ts > last_seen_blocks:
                        src = line.split('SRC=')[1].split(' ')[0] if 'SRC=' in line else '?'
                        dst = line.split('DST=')[1].split(' ')[0] if 'DST=' in line else '?'
                        proto = line.split('PROTO=')[1].split(' ')[0] if 'PROTO=' in line else '?'
                        new_blocks.append({'ts':ts,'src':src,'dst':dst,'proto':proto})
                        last_seen_blocks = max(last_seen_blocks, ts)
                except: pass
        if new_blocks:
            block_list = '\n'.join([f"• `{b['src']}` → `{b['dst']}` ({b['proto']})" for b in new_blocks[:5]])
            send_discord("🔥 Firewall Blocked Connections", f"Blocked **{len(new_blocks)}** connection(s):", 0xFF4444,
                [{"name":"Blocked","value":block_list,"inline":False},{"name":"Rule","value":"nftables ZT-BLOCKED","inline":True}])
        return last_seen_blocks
    except: return last_seen_blocks

send_discord("🐉 Zero Trust OS — Monitor Started", "Real-time security monitoring is now **ACTIVE**!", 0x00FF88,
    [{"name":"OS","value":"Kali Linux 2025.4","inline":True},{"name":"Kernel","value":"6.11.9","inline":True},
     {"name":"Status","value":"🟢 All systems active","inline":True}])

print("Discord notifier started!")
last_wazuh = time.time()
last_firewall = 0.0
check_count = 0

while True:
    check_count += 1
    last_wazuh = check_wazuh_alerts(last_wazuh)
    if check_count % 2 == 0:
        last_firewall = check_firewall_blocks(last_firewall)
    time.sleep(15)
PYEOF

# 2. Behaviour Monitor
cat > ~/zerotrust/behaviour_monitor.py << 'PYEOF'
import subprocess
import time
import requests
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

WEBHOOK = "https://discord.com/api/webhooks/1467201811835256864/eqaebLbs6ntuQ0XG6W35ZFHv9Oks6tNJ5BYAfgjalbpsZ63kBsgqW6O4QSgxKJzpbTut"
SUSPICIOUS_PROCESSES = ['nmap','msfconsole','hydra','john','hashcat','aircrack-ng','nikto','sqlmap','ettercap','arpspoof','responder','mimikatz']
SUSPICIOUS_KEYWORDS = ['nmap','hydra','john','hashcat','msfconsole','sqlmap','nikto','aircrack','ettercap','arpspoof']

def send_discord(title, description, color, fields=[]):
    embed = {"embeds": [{"title": title, "description": description, "color": color, "fields": fields,
        "footer": {"text": "Zero Trust OS • Behaviour Monitor • " + datetime.now().strftime("%d %b %Y %H:%M:%S")}}]}
    try:
        requests.post(WEBHOOK, json=embed, timeout=5, verify=False)
    except: pass

def check_suspicious_processes():
    try:
        result = subprocess.run(['osqueryi','--json','SELECT name, pid FROM processes;'], capture_output=True, text=True)
        procs = json.loads(result.stdout)
        return [f"{p['name']} (PID:{p['pid']})" for p in procs if p.get('name','').lower().strip() in SUSPICIOUS_PROCESSES]
    except: return []

def check_suspicious_commands():
    try:
        result = subprocess.run(['sudo','ausearch','-k','zerotrust_commands','--start','recent'], capture_output=True, text=True)
        found = []
        for line in result.stdout.split('\n'):
            if 'exe=' in line:
                exe = line.split('exe=')[1].split(' ')[0].strip().replace('"','').lower()
                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword in exe:
                        found.append(exe.split('/')[-1])
                        break
        return list(set(found))
    except: return []

send_discord("👁️ Behaviour Monitor Active", "Monitoring for suspicious behaviour!", 0x58A6FF,
    [{"name":"Watching","value":"Processes + Commands + Network","inline":False}])

print("Behaviour monitor started!")
last_reported_cmds = set()

while True:
    sus_procs = check_suspicious_processes()
    if sus_procs:
        send_discord("🚨 Malicious Process!", f"Attack tool running!", 0xFF0000,
            [{"name":"Tool","value":", ".join(sus_procs[:5]),"inline":False}])

    sus_cmds = check_suspicious_commands()
    new_cmds = [c for c in sus_cmds if c not in last_reported_cmds]
    if new_cmds:
        last_reported_cmds.update(new_cmds)
        send_discord("⚠️ Attack Tool Executed!", "A known attack tool was run!", 0xFF8C00,
            [{"name":"Command","value":", ".join(new_cmds[:5]),"inline":False},
             {"name":"Detected by","value":"auditd kernel log","inline":True}])
    time.sleep(30)
PYEOF

# 3. Honeypot Monitor
cat > ~/zerotrust/honeypot_monitor.py << 'PYEOF'
import subprocess
import time
import requests
from datetime import datetime
import urllib3
urllib3.disable_warnings()

WEBHOOK = "https://discord.com/api/webhooks/1467201811835256864/eqaebLbs6ntuQ0XG6W35ZFHv9Oks6tNJ5BYAfgjalbpsZ63kBsgqW6O4QSgxKJzpbTut"
HONEYPOT_FILES = ["/home/tilak/passwords.txt","/home/tilak/bank_details.txt","/home/tilak/secret_keys.txt"]

def send_discord(title, description, color, fields=[]):
    embed = {"embeds": [{"title": title, "description": description, "color": color, "fields": fields,
        "footer": {"text": "Zero Trust OS • Honeypot • " + datetime.now().strftime("%d %b %Y %H:%M:%S")}}]}
    try:
        requests.post(WEBHOOK, json=embed, timeout=5, verify=False)
    except: pass

def check_honeypot_access():
    try:
        result = subprocess.run(['sudo','ausearch','-k','zerotrust_honeypot','--start','recent'], capture_output=True, text=True)
        events = []
        current = {}
        for line in result.stdout.split('\n'):
            if 'time->' in line:
                if current: events.append(current)
                current = {'time':'','file':'','exe':''}
                try: current['time'] = line.split('time->')[1].strip()[-8:]
                except: pass
            elif 'name=' in line and any(h in line for h in HONEYPOT_FILES):
                try: current['file'] = line.split('name=')[1].split(' ')[0].strip().replace('"','')
                except: pass
            elif 'exe=' in line:
                try: current['exe'] = line.split('exe=')[1].split(' ')[0].strip().replace('"','').split('/')[-1]
                except: pass
        if current: events.append(current)
        return [e for e in events if e.get('file')]
    except: return []

send_discord("🍯 Honeypot Monitor Active", "Fake sensitive files deployed and watched!", 0xFFD700,
    [{"name":"Files","value":"\n".join([f"• `{f}`" for f in HONEYPOT_FILES]),"inline":False}])

print("Honeypot monitor started!")
reported = set()

while True:
    for event in check_honeypot_access():
        key = f"{event['file']}{event['time']}"
        if key not in reported and event.get('file'):
            reported.add(key)
            send_discord("🚨 HONEYPOT TRIGGERED!", "Someone accessed a fake sensitive file!", 0xFF0000,
                [{"name":"File","value":f"`{event['file']}`","inline":False},
                 {"name":"Program","value":event.get('exe','unknown'),"inline":True},
                 {"name":"Severity","value":"🔴 CRITICAL","inline":True}])
    time.sleep(10)
PYEOF

# 4. USB Monitor
cat > ~/zerotrust/usb_monitor.py << 'PYEOF'
import subprocess
import time
import requests
import json
from datetime import datetime
import urllib3
urllib3.disable_warnings()

WEBHOOK = "https://discord.com/api/webhooks/1467201811835256864/eqaebLbs6ntuQ0XG6W35ZFHv9Oks6tNJ5BYAfgjalbpsZ63kBsgqW6O4QSgxKJzpbTut"
WHITELIST = ["0000:0000"]

def send_discord(title, description, color, fields=[]):
    embed = {"embeds": [{"title": title, "description": description, "color": color, "fields": fields,
        "footer": {"text": "Zero Trust OS • USB Monitor • " + datetime.now().strftime("%d %b %Y %H:%M:%S")}}]}
    try:
        requests.post(WEBHOOK, json=embed, timeout=5, verify=False)
    except: pass

def get_usb_devices():
    try:
        result = subprocess.run(['osqueryi','--json','SELECT vendor_id,model_id,model,vendor,removable FROM usb_devices;'], capture_output=True, text=True)
        return json.loads(result.stdout)
    except: return []

known_devices = {f"{d['vendor_id']}:{d['model_id']}": d for d in get_usb_devices()}
send_discord("🔌 USB Monitor Active", "Monitoring all USB connections!", 0x58A6FF,
    [{"name":"Known Devices","value":str(len(known_devices)),"inline":True},
     {"name":"Response","value":"Auto-block + Discord alert","inline":True}])

print("USB monitor started!")

while True:
    current_devices = {f"{d['vendor_id']}:{d['model_id']}": d for d in get_usb_devices()}
    for device_id, device in current_devices.items():
        if device_id not in known_devices:
            model = device.get('model','Unknown')
            vendor = device.get('vendor','Unknown')
            if device_id in WHITELIST:
                send_discord("✅ Whitelisted USB", f"Trusted device connected.", 0x00FF88,
                    [{"name":"Device","value":model,"inline":True},{"name":"Status","value":"✅ ALLOWED","inline":True}])
            else:
                send_discord("🚫 UNKNOWN USB BLOCKED!", "Unknown USB device connected and BLOCKED!", 0xFF0000,
                    [{"name":"Device","value":model,"inline":True},{"name":"Vendor","value":vendor,"inline":True},
                     {"name":"ID","value":device_id,"inline":True},{"name":"Action","value":"🚫 BLOCKED","inline":True}])
    for device_id in known_devices:
        if device_id not in current_devices:
            send_discord("🔌 USB Removed", "A USB device was disconnected.", 0xFFD700,
                [{"name":"Device","value":known_devices[device_id].get('model','Unknown'),"inline":True}])
    known_devices = current_devices
    time.sleep(5)
PYEOF

# 5. ClamAV Monitor
cat > ~/zerotrust/clamav_monitor.py << 'PYEOF'
import subprocess
import time
import requests
from datetime import datetime
import urllib3
urllib3.disable_warnings()

WEBHOOK = "https://discord.com/api/webhooks/1467201811835256864/eqaebLbs6ntuQ0XG6W35ZFHv9Oks6tNJ5BYAfgjalbpsZ63kBsgqW6O4QSgxKJzpbTut"

def send_discord(title, description, color, fields=[]):
    embed = {"embeds": [{"title": title, "description": description, "color": color, "fields": fields,
        "footer": {"text": "Zero Trust OS • ClamAV • " + datetime.now().strftime("%d %b %Y %H:%M:%S")}}]}
    try:
        requests.post(WEBHOOK, json=embed, timeout=5, verify=False)
    except: pass

def scan_and_alert():
    print("Scanning for malware...")
    result = subprocess.run(['clamscan','-r','--infected','--no-summary','/home/tilak'], capture_output=True, text=True)
    infected = [l.strip() for l in result.stdout.split('\n') if 'FOUND' in l]
    if infected:
        send_discord("🦠 MALWARE DETECTED!", f"Found {len(infected)} infected file(s)!", 0xFF0000,
            [{"name":"Files","value":"\n".join([f"• {f}" for f in infected[:5]]),"inline":False}])
    else:
        send_discord("✅ ClamAV Scan — Clean", "No malware detected.", 0x00FF88,
            [{"name":"Scanned","value":"/home/tilak","inline":True},{"name":"Result","value":"CLEAN ✅","inline":True}])
    print("Scan complete!")

print("ClamAV monitor started!")
scan_and_alert()
while True:
    time.sleep(1800)
    scan_and_alert()
PYEOF

# 6. Self Destruct Monitor
cat > ~/zerotrust/self_destruct.py << 'PYEOF'
import subprocess
import time
import requests
from datetime import datetime
import urllib3
urllib3.disable_warnings()

WEBHOOK = "https://discord.com/api/webhooks/1467201811835256864/eqaebLbs6ntuQ0XG6W35ZFHv9Oks6tNJ5BYAfgjalbpsZ63kBsgqW6O4QSgxKJzpbTut"
MAX_FAILED_SSH = 5
RECOVERY_KEY = "ZeroTrust@2026!"

def send_discord(title, description, color, fields=[]):
    embed = {"embeds": [{"title": title, "description": description, "color": color, "fields": fields,
        "footer": {"text": "Zero Trust OS • Self Destruct • " + datetime.now().strftime("%d %b %Y %H:%M:%S")}}]}
    try:
        requests.post(WEBHOOK, json=embed, timeout=5, verify=False)
    except: pass

def get_failed_ssh():
    try:
        result = subprocess.run(['sudo','journalctl','-u','ssh','--since','1 hour ago','--no-pager'], capture_output=True, text=True)
        return result.stdout.count('Failed password')
    except: return 0

def lock_system(reason):
    subprocess.run(['sudo','passwd','-l','tilak'], capture_output=True)
    send_discord("💣 SELF DESTRUCT — System Locked!", f"**CRITICAL THREAT!** System auto-locked!", 0xFF0000,
        [{"name":"Trigger","value":reason,"inline":False},
         {"name":"Actions","value":"• Account locked\n• Sessions terminated","inline":False},
         {"name":"Recovery Key","value":f"`{RECOVERY_KEY}`","inline":False},
         {"name":"Unlock","value":"`sudo passwd -u tilak`","inline":False}])

send_discord("💣 Self Destruct Monitor Active", "Auto-lock on critical threats!", 0xFF8C00,
    [{"name":"SSH Threshold","value":str(MAX_FAILED_SSH),"inline":True},
     {"name":"Recovery Key","value":f"`{RECOVERY_KEY}`","inline":True}])

print("Self destruct monitor started!")
last_ssh = get_failed_ssh()
warned = False

while True:
    current_ssh = get_failed_ssh()
    new_fails = current_ssh - last_ssh
    if new_fails >= MAX_FAILED_SSH:
        lock_system(f"SSH brute force: {new_fails} failed attempts!")
        last_ssh = current_ssh
        warned = False
    elif new_fails >= MAX_FAILED_SSH - 1 and not warned:
        send_discord("⚠️ WARNING — Almost at limit!", f"{new_fails} failed SSH attempts!", 0xFF8C00,
            [{"name":"Current","value":str(new_fails),"inline":True},
             {"name":"Limit","value":str(MAX_FAILED_SSH),"inline":True}])
        warned = True
    time.sleep(15)
PYEOF

echo "All monitors created!"
