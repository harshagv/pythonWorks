#!/bin/bash
# OpenVPN Server & Client Setup Script on jump host (Ubuntu)
# Run this script as root or with sudo.

### ===== COLOR CONSTANTS ===== ###
RESET="\033[0m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
PINK="\033[1;35m"
CYAN="\033[1;36m"

### ===== PRINT FUNCTIONS ===== ###
print_info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
print_warn() { echo -e "${YELLOW}[WARNING]${RESET} $1"; }
print_error() { echo -e "${RED}[ERROR]${RESET} $1"; }
print_title() { echo -e "\n${PINK}=== $1 ===${RESET}\n"; }

set -e

# Config
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_DIR="/etc/openvpn"
CLIENT_NAME="kali"
PUBLIC_IF_IP="192.88.100.11"       # <-- Replace this with your jump host publicNAT IP reachable by kali VM
# PUBLIC_IF="enp0s9"               # <-- Replace this with your jump host publicNAT interface
JUMP_HOST_PRIVATE_IP="10.0.10.5"   # <-- Replace this with the private IP of THIS jump host
APP_SERVER_IP="10.0.10.10"         # <-- Replace this with private IP of your target app server (VM A)
# PUBLIC_IF=$(ip route | grep default | awk '{print $5}')
VPN_NET="10.8.0.0 255.255.255.0"
FORWARD_FROM_PORT=80

# Automatically Detect Network Interfaces
PUBLIC_IF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
PRIVATE_IF=$(ip -4 route get ${APP_SERVER_IP} | grep -Po '(?<=dev )(\S+)' | head -1)
PRIVATE_NET=$(ip -4 route get ${APP_SERVER_IP} | grep -Po '(?<=src )(\S+)' | head -1 | cut -d. -f1-3).0/24

# Verification
if [[ -z "$PUBLIC_IF" || -z "$PRIVATE_IF" ]]; then
    print_error "Could not automatically detect public or private network interfaces."
    print_info "Please set PUBLIC_IF and PRIVATE_IF manually at the top of the script."
    exit 1
fi

print_title "Detected Network Configuration"
print_info "Public IP:         ${PUBLIC_IF_IP}"
print_info "Public Interface:    ${PUBLIC_IF}"
print_info "Private Interface:   ${PRIVATE_IF}"
print_info "Private Network:     ${PRIVATE_NET}"
print_info "App Server IP:       ${APP_SERVER_IP}"
echo "Press Enter to continue or Ctrl+C to cancel."
read < /dev/tty

# ALLOW port binding for port 80
print_info "ALLOW port binding for port 80"
setcap 'cap_net_bind_service=+ep' /usr/bin/ssh

print_title "Step 1: Installing OpenVPN and EasyRSA (if needed).."
apt update
apt install -y openvpn easy-rsa

print_title "Step 2: Setting up EasyRSA (PKI).."

make-cadir $EASYRSA_DIR
cd $EASYRSA_DIR

### Preconfigure vars for silent CA creation
cat > vars <<EOF
set_var EASYRSA_BATCH "yes"
set_var EASYRSA_REQ_CN    "OpenVPN-CA"
set_var EASYRSA_REQ_COUNTRY    "AU"
set_var EASYRSA_REQ_PROVINCE   "NSW"
set_var EASYRSA_REQ_CITY       "Sydney"
set_var EASYRSA_REQ_ORG        "MyVPN"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "VPN"
EOF

# Initialize the Public Key Infrastructure (PKI) directory
./easyrsa init-pki

# Build the CA (Certificate Authority) without passphrase (for automation)
echo | ./easyrsa build-ca nopass

print_title "Step 3: Building server certificate & keys.."
./easyrsa gen-req server nopass
./easyrsa sign-req server server

print_title "Step 4: Generate Diffie-Hellman parameters.."
./easyrsa gen-dh

print_title "Step 5: Generate HMAC key to defend against DoS attacks.."
openvpn --genkey --secret ta.key

print_title "Step 6: Generate client certificates.."
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

print_title "Step 7: Copying keys and certs to OpenVPN directory.."

cp pki/ca.crt $OPENVPN_DIR
cp pki/issued/server.crt $OPENVPN_DIR
cp pki/private/server.key $OPENVPN_DIR
cp pki/dh.pem $OPENVPN_DIR/dh2048.pem
cp ta.key $OPENVPN_DIR
cp pki/issued/${CLIENT_NAME}.crt $OPENVPN_DIR
cp pki/private/${CLIENT_NAME}.key $OPENVPN_DIR

print_title "Step 8: Creating server configuration file.."

cat > $OPENVPN_DIR/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
auth SHA256
tls-auth ta.key 0
topology subnet
server $VPN_NET
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
# --- PUSH ROUTES TO CLIENT ---
push "route ${PRIVATE_NET}"
push "redirect-gateway def1 bypass-dhcp"
# --- END PUSH ROUTES ---
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
EOF

print_title "Step 9: Enable IP forwarding.."

sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

print_title "Step 10: Setting up UFW to allow OpenVPN traffic and enable forwarding.."

ufw allow 1194/udp
ufw allow OpenSSH
ufw route allow in on tun0 out on ${EXTERNAL_IF}
ufw allow ${FORWARD_FROM_PORT}/tcp

# Adjust UFW before.rules for NAT
if ! grep -q "# START OPENVPN RULES" /etc/ufw/before.rules; then
  sed -i "1i# START OPENVPN RULES\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/24 -o $EXTERNAL_IF -j MASQUERADE\nCOMMIT\n# END OPENVPN RULES\n" /etc/ufw/before.rules

fi

sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw


# # Define the NAT rules block
# UFW_NAT_RULES="
# # START OPENVPN & PORT FORWARDING RULES
# *nat
# :PREROUTING ACCEPT [0:0]
# :POSTROUTING ACCEPT [0:0]
# # 1. Port Forwarding Rule for the App on VM A
# -A PREROUTING -i ${PUBLIC_IF} -p tcp --dport ${FORWARD_FROM_PORT} -j DNAT --to-destination ${APP_SERVER_IP}:${FORWARD_TO_PORT}
# # 2. Masquerade traffic from VPN to the Internet
# -A POSTROUTING -s ${VPN_NET} -o ${PUBLIC_IF} -j MASQUERADE
# # 3. Masquerade traffic from VPN to the Private LAN
# -A POSTROUTING -s ${VPN_NET} -d ${PRIVATE_NET} -o ${PRIVATE_IF} -j MASQUERADE
# COMMIT
# # END OPENVPN & PORT FORWARDING RULES
# "

# # Check if rules already exist, if not, prepend them to before.rules
# if ! grep -q "# START OPENVPN & PORT FORWARDING RULES" /etc/ufw/before.rules; then
#   print_info "Adding NAT rules to /etc/ufw/before.rules..."
#   (echo "$UFW_NAT_RULES"; cat /etc/ufw/before.rules) > /tmp/before.rules.tmp
#   mv /tmp/before.rules.tmp /etc/ufw/before.rules
# else
#   print_warn "NAT rules already seem to exist in /etc/ufw/before.rules. Skipping."
# fi


CLIENT_NAME="kali"
OPENVPN_DIR="/etc/openvpn"

#USER_HOME=$(eval echo ~$TARGET_USER)
CLIENT_NAME="kali"
OPENVPN_DIR="/etc/openvpn"

# Detect the non-root user who invoked sudo
TARGET_USER=$(logname 2>/dev/null || echo $SUDO_USER)
USER_HOME=$(eval echo ~$TARGET_USER)

CLIENT_CONFIG="${USER_HOME}/${CLIENT_NAME}.ovpn"


cat > $CLIENT_CONFIG <<EOF
client
dev tun
proto udp
remote $PUBLIC_IF_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
key-direction 1
verb 3

<ca>
$(cat $OPENVPN_DIR/ca.crt)
</ca>
<cert>
$(awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' $OPENVPN_DIR/${CLIENT_NAME}.crt)
</cert>
<key>
$(cat $OPENVPN_DIR/${CLIENT_NAME}.key)
</key>
<tls-auth>
$(cat $OPENVPN_DIR/ta.key)
</tls-auth>
EOF

# Change ownership to the invoking non-root user
chown "$TARGET_USER:$TARGET_USER" "$CLIENT_CONFIG"

# Restrict permissions so only they can read/write
chmod 600 "$CLIENT_CONFIG"

print_success "Client config saved to $CLIENT_CONFIG (owned by $TARGET_USER)"

# Step 11 — Starting OpenVPN
print_title "Step 11: Starting OpenVPN.."
systemctl enable openvpn@server.service --now
systemctl start openvpn@server.service
systemctl status openvpn@server.service --no-pager --quiet


# --- Function to display the final signature ---
print_signature() {
    echo
    if command -v get_language_message >/dev/null 2>&1; then
        # Assuming get_language_message is a function that might exist
        # to provide translations or special formatting.
        final_message=$(get_language_message "\\033[1;32mCreated with ♡, Harsha")
        echo -e "$final_message"
    else
        # Default fallback if the function doesn't exist
        echo -e "\033[92mCreated with ♡, Harsha\033[0m"
    fi
}

print_info "[✔] Full OpenVPN Server & Client Setup installation complete."
print_signature






#!/bin/bash
# Client Side
# sudo apt update
# sudo apt install openvpn openvpn-systemd-resolved network-manager-openvpn network-manager-openvpn-gnome -y
# scp user@jump_host_ip:~/kali.ovpn ~/Downloads/
# ip addr show tun0
# http://<private_ip_of_app_vm>/dvwa/
# tee -a ~/Downloads/kali.ovpn <<EOF
# script-security 2
# up /etc/openvpn/update-resolv-conf
# down /etc/openvpn/update-resolv-conf
# EOF
# tail -n 3 ~/Downloads/kali.ovpn
# sudo openvpn --config ~/Downloads/kali.ovpn

