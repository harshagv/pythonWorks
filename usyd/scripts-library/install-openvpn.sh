#!/bin/bash
# OpenVPN Server & Client Setup Script on jump host (Ubuntu)
# Run this script as root or with sudo.

set -e

# === Config ===
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_DIR="/etc/openvpn"
CLIENT_NAME="kali"
SERVER_IP="192.168.11.7"  # <-- Replace this with your jump host public/private IP reachable by client
VPN_NET="10.8.0.0 255.255.255.0"
EXTERNAL_IF="enp0s3"
# EXTERNAL_IF=$(ip route | grep default | awk '{print $5}')


echo "Step 1: Installing OpenVPN and EasyRSA (if needed)..."
apt update
apt install -y openvpn easy-rsa

echo "Step 2: Setting up EasyRSA (PKI)..."

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

echo "Step 3: Building server certificate & keys..."
./easyrsa gen-req server nopass
./easyrsa sign-req server server

echo "Step 4: Generate Diffie-Hellman parameters..."
./easyrsa gen-dh

echo "Step 5: Generate HMAC key to defend against DoS attacks..."
openvpn --genkey --secret ta.key

echo "Step 6: Generate client certificates..."
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

echo "Step 7: Copying keys and certs to OpenVPN directory..."

cp pki/ca.crt $OPENVPN_DIR
cp pki/issued/server.crt $OPENVPN_DIR
cp pki/private/server.key $OPENVPN_DIR
cp pki/dh.pem $OPENVPN_DIR/dh2048.pem
cp ta.key $OPENVPN_DIR
cp pki/issued/${CLIENT_NAME}.crt $OPENVPN_DIR
cp pki/private/${CLIENT_NAME}.key $OPENVPN_DIR

echo "Step 8: Creating server configuration file..."

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

echo "Step 9: Enable IP forwarding..."

sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

echo "Step 10: Setting up UFW to allow OpenVPN traffic and enable forwarding..."

ufw allow 1194/udp
ufw allow OpenSSH

# Adjust UFW before.rules for NAT
if ! grep -q "# START OPENVPN RULES" /etc/ufw/before.rules; then
  sed -i "1i# START OPENVPN RULES\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/24 -o $EXTERNAL_IF -j MASQUERADE\nCOMMIT\n# END OPENVPN RULES\n" /etc/ufw/before.rules

fi

sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw


# if ! grep -q "# START OPENVPN RULES" /etc/ufw/before.rules; then
# cat <<EOF | cat - /etc/ufw/before.rules > /tmp/before.rules && mv /tmp/before.rules /etc/ufw/before.rules
# # START OPENVPN RULES
# *nat
# :POSTROUTING ACCEPT [0:0]
# -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
# COMMIT
# # END OPENVPN RULES

# EOF
# fi



CLIENT_NAME="kali"
OPENVPN_DIR="/etc/openvpn"

CLIENT_CONFIG="/root/${CLIENT_NAME}.ovpn"

cat > $CLIENT_CONFIG <<EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
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



