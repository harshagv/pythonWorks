#!/bin/bash
# DVWA & SSH Auto Install Script for Ubuntu
# Usage:
#   sudo bash install-dvwa.sh          # Install SSH + DVWA
#   sudo bash install-dvwa.sh ssh      # Install SSH only
#   sudo bash install-dvwa.sh dvwa      # Install DVWA only

set -e

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

### ===== FUNCTIONS ===== ###

### STEP 1: Install and Configure OpenSSH Server
install_ssh() {
    print_title "=== STEP 1: Install and Configure OpenSSH Server ==="

    echo "Updating system.."
    apt update && apt upgrade -y

    echo "Installing OpenSSH server..."
    apt install -y openssh-server

    echo "Editing SSH configuration: /etc/ssh/sshd_config"
    SSHD_CONFIG="/etc/ssh/sshd_config"
    sed -i 's/^#Port 22/Port 22/' $SSHD_CONFIG
    sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' $SSHD_CONFIG
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' $SSHD_CONFIG

    echo "Configuring UFW firewall for SSH access.."
    ufw status || true
    ufw enable
    ufw allow 22

    echo "Restarting SSH service.."
    systemctl restart ssh

    print_success "OpenSSH server installed successfully!"
}

### STEP 2: DVWA Install and Configuration
install_dvwa() {
    print_title "=== STEP 2: DVWA Install and Configuration ==="

    # ==== CONFIG ====
    DB_NAME="dvwa"
    DB_USER="dvwa"
    DB_HOST="localhost"
    WEB_DIR="/var/www/html/dvwa"
    SERVER_NAME="localhost"
    # SERVER_NAME=${1:-$(hostname -I | awk '{print $1}')}
    # --- Ask for SQL user password ---
    echo -e "\e[96mEnter SQL password for DVWA user (press Enter for default: pass):\e[0m"
    read -s DB_PASS < /dev/tty
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

    echo "Setting permissions.."
    sudo chown -R www-data:www-data /var/www/html/dvwa
    sudo chmod -R 755 /var/www/html/dvwa

    echo "Configuring MariaDB for DVWA.."
    mysql -u root <<EOF
    CREATE DATABASE IF NOT EXISTS ${DB_NAME};
    CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
    GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
    FLUSH PRIVILEGES;
EOF

    echo "Updating DVWA config file.."
    cd "$WEB_DIR/config"
    cp -n config.inc.php.dist config.inc.php
    # Check if the config file exists
    CONFIG_FILE="/var/www/html/dvwa/config/config.inc.php"
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "Error: Configuration file not found at $CONFIG_FILE"
        exit 1
    fi
    # Remove Windows-style carriage returns
    sed -i 's/\r//g' "$CONFIG_FILE"
    # Comment out the original lines and insert new ones
    sed -i "/'db_server'/c\
    \$_DVWA[ 'db_server' ] = '$DB_HOST';
    " "$CONFIG_FILE"
    sed -i "/'db_user'/c\
    \$_DVWA[ 'db_user' ] = '$DB_USER';
    " "$CONFIG_FILE"
    sed -i "/'db_password'/c\
    \$_DVWA[ 'db_password' ] = '$DB_PASS';
    " "$CONFIG_FILE"
    echo "Configuration file updated successfully."

    print_info "Configuring PHP settings for DVWA..."
    PHPINI="/etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/apache2/php.ini"
    sed -i 's/^\s*allow_url_fopen\s*=.*/allow_url_fopen = On/' "$PHPINI"
    sed -i 's/^\s*allow_url_include\s*=.*/allow_url_include = On/' "$PHPINI"


    echo "Restarting Apache.."
    systemctl restart apache2

    ### Apache Configuration for Localhost Only ###
    echo "Setting Apache to localhost-only mode"

    # 1) Set GLOBAL ServerName in apache2.conf to prevent AH00558 warning
    if ! grep -q "ServerName" /etc/apache2/apache2.conf; then
        print_info "Adding global ServerName to apache2.conf"
        echo "ServerName ${SERVER_NAME}" | sudo tee -a /etc/apache2/apache2.conf
    else
        print_info "Updating existing global ServerName in apache2.conf"
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

    echo "Configuring UFW firewall for HTTP access.."
    ufw allow 80
 
    # 4️⃣ Restart Apache
    sudo systemctl restart apache2

    echo "======================================="
    print_success "[✔] DVWA configured successfully!"
    print_title "Global ServerName set to ${SERVER_NAME}"
    curl -I http://localhost/dvwa/setup.php
    print_title "  → Accessible at: http://${SERVER_NAME}/dvwa/setup.php"
    print_title "Default DB User: ${DB_USER}, Password: ${DB_PASS}"
    print_title " Username : admin"
    print_title " Password : password (DVWA default)"
    echo "======================================="
}

# --- Function to display the final signature ---
print_signature() {
    echo
    if command -v get_language_message >/dev/null 2>&1; then
        # Assuming get_language_message is a function that might exist
        # to provide translations or special formatting.
        final_message=$(get_language_message "\\033[1;32mCreated with ♡, Harsha ☺︎")
        echo -e "$final_message"
    else
        # Default fallback if the function doesn't exist
        echo -e "\033[92mCreated with ♡, Harsha ☺︎\033[0m"
    fi
}

### ===== MAIN LOGIC ===== ###
case "$1" in
    "ssh")
        # Handle the 'ssh' argument
        install_ssh
        print_info "[✔] SSH-only installation complete."
        print_signature # Call the signature function
        ;;
    "dvwa")
        # Handle the 'dvwa' argument
        install_dvwa
        print_info "[✔] DVWA installation complete."
        print_signature # Call the signature function
        ;;
    "")
        # Handle the empty argument (no argument provided)
        install_ssh
        install_dvwa
        print_info "[✔] Full SSH + DVWA installation complete."
        print_signature # Call the signature function
        ;;
    *)
        # Handle all other (invalid) arguments
        echo "Usage: $0 [ssh]"
        exit 1
        ;;
esac

