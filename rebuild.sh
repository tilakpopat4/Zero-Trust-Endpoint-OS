#!/bin/bash
echo "==============================="
echo " Zero Trust OS — Rebuilding"
echo "==============================="

echo "1. Installing required packages..."
sudo apt install -y auditd aide clamav clamav-daemon sshpass qrencode nohup

echo "2. Setting up auditd rules..."
sudo bash -c 'cat > /etc/audit/rules.d/zerotrust.rules << RULES
-w /var/log/faillog -p wa -k zerotrust_login
-w /var/log/lastlog -p wa -k zerotrust_login
-w /etc/passwd -p wa -k zerotrust_identity
-w /etc/shadow -p wa -k zerotrust_identity
-w /etc/group -p wa -k zerotrust_identity
-w /etc/sudoers -p wa -k zerotrust_privilege
-a always,exit -F arch=b64 -S execve -k zerotrust_commands
-w /etc/ssh/sshd_config -p wa -k zerotrust_ssh
-w /root -p wa -k zerotrust_root_access
-w /etc/hosts -p wa -k zerotrust_network
-w /sbin/insmod -p x -k zerotrust_kernel
-w /sbin/rmmod -p x -k zerotrust_kernel
RULES'
sudo augenrules --load
sudo systemctl enable auditd
sudo systemctl start auditd

echo "3. Setting up nftables..."
sudo bash -c 'cat > /etc/nftables-zerotrust.conf << RULES
#!/usr/sbin/nft -f
table inet zerotrust {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname lo accept
        ip saddr 192.168.0.0/16 tcp dport 22 accept
        tcp dport {80, 443, 8080, 8181, 5000, 9200, 1514, 1515} accept
        icmp type echo-request accept
        log prefix "ZT-BLOCKED: " drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
RULES'
sudo nft -f /etc/nftables-zerotrust.conf
sudo systemctl enable nftables

echo "4. Setting up ClamAV..."
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-freshclam

echo "5. Setting up honeypot files..."
cat > /home/tilak/passwords.txt << HONEY
# Company Passwords - CONFIDENTIAL
admin_portal: Admin@2024!
database_root: DbRoot#9821
aws_secret: AKIA4EXAMPLE123SECRET
HONEY

cat > /home/tilak/bank_details.txt << HONEY
# Bank Account Details - TOP SECRET
Account: 1234 5678 9012 3456
IFSC: HDFC0001234
Balance: 45,23,000 INR
HONEY

cat > /home/tilak/secret_keys.txt << HONEY
# API Keys - DO NOT SHARE
stripe_key: sk_live_EXAMPLE123456789
github_token: ghp_EXAMPLE123456789
HONEY

sudo auditctl -w /home/tilak/passwords.txt -p rwa -k zerotrust_honeypot
sudo auditctl -w /home/tilak/bank_details.txt -p rwa -k zerotrust_honeypot
sudo auditctl -w /home/tilak/secret_keys.txt -p rwa -k zerotrust_honeypot

echo "6. Setting up AppArmor..."
sudo systemctl enable apparmor
sudo systemctl start apparmor

echo "==============================="
echo " Rebuild Complete!"
echo "==============================="
