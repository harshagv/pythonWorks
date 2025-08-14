#!/bin/bash
# DVWA & SSH Auto Install Script for Ubuntu
# Run with: sudo bash install-dvwa.sh

set -e

### STEP 1: Install and Configure OpenSSH Server

echo "Updating system..."
apt update && apt upgrade -y

echo "Installing OpenSSH server..."
apt install -y openssh-server

echo "Editing SSH configuration: /etc/ssh/sshd_config"
SSHD_CONFIG="/etc/ssh/sshd_config"
sed -i 's/^#Port 22/Port 22/' $SSHD_CONFIG
sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' $SSHD_CONFIG
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' $SSHD_CONFIG

echo "Configuring UFW firewall for SSH access..."
ufw status || true
ufw enable
ufw allow 22

echo "Restarting SSH service..."
systemctl restart ssh

### STEP 2: DVWA Install and Configuration

# ==== CONFIG ====
DB_NAME="dvwa"
DB_USER="dvwa"
DB_HOST="localhost"
WEB_DIR="/var/www/html/dvwa"
SERVER_NAME="localhost"
# SERVER_NAME=${1:-$(hostname -I | awk '{print $1}')}
# --- Ask for SQL user password ---
echo -e "\e[96mEnter SQL password for DVWA user (press Enter for default: pass):\e[0m"
read -s DB_PASS
echo
DB_PASS=${DB_PASS:-pass}

echo "Installing required packages for DVWA..."
apt install -y apache2 mariadb-server php php-mysqli php-gd php-zip php-json php-bcmath php-xml libapache2-mod-php git

echo "Enabling and starting Apache & MariaDB..."
systemctl enable apache2 --now
systemctl enable mariadb --now

echo "Cloning DVWA repository..."
cd /var/www/html
if [ -d "DVWA" ] || [ -d "dvwa" ]; then
    echo "DVWA folder already exists, skipping clone..."
else
    git clone https://github.com/digininja/DVWA.git
    mv DVWA dvwa
fi

echo "Setting permissions..."
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa

echo "Configuring MariaDB for DVWA..."
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
EOF

echo "Updating DVWA config file..."
cd "$WEB_DIR/config"
cp -n config.inc.php.dist config.inc.php
sed -i "s|^\(\s*\$_DVWA\['db_server'\]\s*=\s*\).*$|\1'${DB_HOST}';|" config.inc.php
sed -i "s|^\(\s*\$_DVWA\['db_user'\]\s*=\s*\).*$|\1'${DB_USER}';|" config.inc.php
sed -i "s|^\(\s*\$_DVWA\['db_password'\]\s*=\s*\).*$|\1'${DB_PASS}';|" config.inc.php

echo "Configuring PHP settings for DVWA..."
PHPINI="/etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/apache2/php.ini"
sed -i 's/^\s*allow_url_fopen\s*=.*/allow_url_fopen = On/' "$PHPINI"
sed -i 's/^\s*allow_url_include\s*=.*/allow_url_include = On/' "$PHPINI"


echo "Restarting Apache..."
systemctl restart apache2

### Apache Configuration for Localhost Only ###
echo "[INFO] Setting Apache to localhost-only mode"

# 1) Set GLOBAL ServerName in apache2.conf to prevent AH00558 warning
if ! grep -q "ServerName" /etc/apache2/apache2.conf; then
    echo "[INFO] Adding global ServerName to apache2.conf"
    echo "ServerName ${SERVER_NAME}" | sudo tee -a /etc/apache2/apache2.conf
else
    echo "[INFO] Updating existing global ServerName in apache2.conf"
    sudo sed -i "s/^ServerName.*/ServerName ${SERVER_NAME}/" /etc/apache2/apache2.conf
fi

# 2) Set Apache to listen only on 127.0.0.1:80
sed -i 's/^Listen .*/Listen 80/' /etc/apache2/ports.conf

# 3) Create DVWA VirtualHost config
sudo tee /etc/apache2/sites-available/dvwa.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName ${SERVER_NAME}
    DocumentRoot /var/www/html

    <Directory /var/www/html/dvwa>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/dvwa_error.log
    CustomLog \${APACHE_LOG_DIR}/dvwa_access.log combined
</VirtualHost>
EOF

# 3️⃣ Enable site and modules
sudo a2ensite dvwa.conf
sudo a2enmod rewrite
sudo a2dissite 000-default.conf
sudo apache2ctl configtest
sudo apache2ctl -S

# 4️⃣ Restart Apache
sudo systemctl restart apache2

echo "======================================="
echo "DVWA configured successfully!"
echo "Global ServerName set to ${SERVER_NAME}"
curl -I http://localhost/dvwa/setup.php
echo "  → Accessible at: http://${SERVER_NAME}/dvwa/setup.php"
echo "Default DB User: ${DB_USER}, Password: ${DB_PASS}"
echo " Username : admin"
echo " Password : password (DVWA default)"
echo "======================================="


# --- Final Signature Message ---
echo
if command -v get_language_message >/dev/null 2>&1; then
    final_message=$(get_language_message "\\033[95mWith ♡ by Harsha")
    echo -e "$final_message"
else
    echo -e "\033[95mWith ♡ by Harsha\033[0m"
fi

