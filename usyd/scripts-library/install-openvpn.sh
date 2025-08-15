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

# === Config ===
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_DIR="/etc/openvpn"
CLIENT_NAME="kali"
SERVER_IP="192.168.11.7"  # <-- Replace this with your jump host publicNAT IP reachable by kali VM
VPN_NET="10.8.0.0 255.255.255.0"
EXTERNAL_IF="enp0s3"      # <-- Replace this with your jump host publicNAT interface
# EXTERNAL_IF=$(ip route | grep default | awk '{print $5}')


print_title "Step 1: Installing OpenVPN and EasyRSA (if needed)..."
apt update
apt install -y openvpn easy-rsa

print_title "Step 2: Setting up EasyRSA (PKI)..."

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

print_title "Step 3: Building server certificate & keys..."
./easyrsa gen-req server nopass
./easyrsa sign-req server server

print_title "Step 4: Generate Diffie-Hellman parameters..."
./easyrsa gen-dh

print_title "Step 5: Generate HMAC key to defend against DoS attacks..."
openvpn --genkey --secret ta.key

print_title "Step 6: Generate client certificates..."
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

print_title "Step 7: Copying keys and certs to OpenVPN directory..."

cp pki/ca.crt $OPENVPN_DIR
cp pki/issued/server.crt $OPENVPN_DIR
cp pki/private/server.key $OPENVPN_DIR
cp pki/dh.pem $OPENVPN_DIR/dh2048.pem
cp ta.key $OPENVPN_DIR
cp pki/issued/${CLIENT_NAME}.crt $OPENVPN_DIR
cp pki/private/${CLIENT_NAME}.key $OPENVPN_DIR

print_title "Step 8: Creating server configuration file..."

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

print_title "Step 9: Enable IP forwarding..."

sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

print_title "Step 10: Setting up UFW to allow OpenVPN traffic and enable forwarding..."

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

#USER_HOME=$(eval echo ~$TARGET_USER)
CLIENT_CONFIG="${HOME}/${CLIENT_NAME}.ovpn"

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

chown "$USER:$USER" "$CLIENT_CONFIG"
chmod 655 "$CLIENT_CONFIG"

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

print_title "Step 11: Configuring Passwordless Sudo for File Transfer..."

# Determine the non-root user who invoked sudo.
# This is crucial for setting up the correct permissions.
if [ -z "$SUDO_USER" ]; then
    print_error "This script must be run via sudo by a regular user (e.g., 'sudo $0')."
    print_error "Direct execution by the root user is not supported for this step."
    exit 1
fi

# Define the new sudoers file for our user
SUDOERS_FILE="/etc/sudoers.d/99-allow-file-transfer-${SUDO_USER}"

# The content to be added to the sudoers file
SUDOERS_CONTENT="${SUDO_USER} ALL=(ALL) NOPASSWD: /bin/cat, /bin/tar"

# Check if the file already exists and contains the correct content
if [ -f "$SUDOERS_FILE" ] && grep -qF -- "$SUDOERS_CONTENT" "$SUDOERS_FILE"; then
    print_info "Sudoers rule for '${SUDO_USER}' already exists and is correct. Skipping."
else
    print_info "Creating sudoers rule for user '${SUDO_USER}' to allow passwordless file transfer."
    
    # Create the new sudoers file with the correct content and permissions.
    # Using 'tee' as root ensures the file is written correctly.
    echo "$SUDOERS_CONTENT" | sudo tee "$SUDOERS_FILE" > /dev/null
    
    # Set the correct, secure permissions for the sudoers file
    sudo chmod 0440 "$SUDOERS_FILE"
    
    # Verify the syntax of the new file to prevent system issues
    if visudo -c -f "$SUDOERS_FILE"; then
        print_success "Successfully created and validated sudoers file: $SUDOERS_FILE"
    else
        print_error "Failed to create a valid sudoers file. Removing incorrect file."
        sudo rm -f "$SUDOERS_FILE"
        exit 1
    fi
fi


print_info "[✔] Full OpenVPN Server & Client Setup installation complete."
print_signature



# Client Side
# sudo apt update
# sudo apt install openvpn network-manager-openvpn network-manager-openvpn-gnome -y
# scp user@jump_host_ip:~/kali.ovpn ~/Downloads/
## Method 1 (scp)
# scp -o "ProxyCommand ssh user@jump_host_ip sudo cat %h:%p" localhost:/root/kali.ovpn .
## Method 3 (tar)
# ssh user@jump_host_ip "sudo tar -czf - -C /root kali.ovpn" | tar -xzf -
# ip addr show tun0
# http://<private_ip_of_app_vm>/dvwa/
# sudo openvpn --config ~/Downloads/kali.ovpn
