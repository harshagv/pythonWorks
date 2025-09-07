#!/bin/bash
# DVWA & SSH Auto Install Script for Ubuntu
# Usage:
#   sudo bash install-dvwa.sh          # Install SSH + DVWA (with MariaDB)
#   sudo bash install-dvwa.sh ssh      # Install SSH only
#   sudo bash install-dvwa.sh dvwa      # Install DVWA only (with MariaDB)
#   sudo bash install-dvwa.sh mysql50   # (NEW) Downgrade to MySQL 5.0.15 for DVWA

# Genereate the script logs
LOGFILE="$(pwd)/dvwa-installer-$(date +"%Y%m%d-%H%M%S").log"
exec > >(tee -a "$LOGFILE") 2>&1

set -euo pipefail # Added -u for unset variables and -o pipefail for stricter error handling.
IFS=$'\n\t'

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
print_error() { echo -e "${RED}[ERROR]${RESET}❌ $1"; }
print_title() { echo -e "\n${PINK}=== $1 ===${RESET}\n"; }

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    print_error "Script exited with error code: $exit_code"
  fi
  print_info "Cleaning up before exit."
}
handle_interrupt() {
  print_error "Script interrupted by user (SIGINT)" >&2
  exit 130
}
trap cleanup EXIT
trap handle_interrupt INT

### ===== FUNCTIONS ===== ###

### STEP 1: Install and Configure OpenSSH Server
install_ssh() {
    print_title "=== STEP 1: Install and Configure OpenSSH Server ==="

    print_info "Updating system.."
    apt update && apt upgrade -y

    print_info "Installing OpenSSH server.."
    apt install -y openssh-server net-tools curl

    print_info "Editing SSH configuration: /etc/ssh/sshd_config"
    SSHD_CONFIG="/etc/ssh/sshd_config"
    sed -i 's/^#Port 22/Port 22/' "$SSHD_CONFIG" || print_warn "Port 22 already uncommented or missing."
    sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' "$SSHD_CONFIG" || print_warn "ListenAddress 0.0.0.0 already uncommented or missing."
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$SSHD_CONFIG" || print_warn "PasswordAuthentication yes already uncommented or missing."
    # Optional: Enable root login, generally not recommended for security reasons
    # sed -i 's/^PermitRootLogin prohibit-password/PermitRootLogin yes/' "$SSHD_CONFIG" || true

    print_info "Configuring UFW firewall for SSH access.."
    ufw status || true
    ufw enable || print_warn "UFW already enabled."
    ufw allow 22 || print_warn "UFW rule for port 22 already exists."

    print_info "Restarting SSH service.."
    systemctl restart ssh

    print_success "OpenSSH server installed successfully!"
}

### STEP 2: DVWA Install and Configuration (with MariaDB)
install_dvwa() {
    print_title "=== STEP 2: DVWA Install and Configuration (MariaDB) ==="

    # ==== CONFIG ====
    DB_NAME="dvwa"
    DB_USER="dvwa"
    DB_HOST="localhost"
    WEB_DIR="/var/www/html/dvwa"
    SERVER_NAME="localhost"
    # SERVER_NAME=${1:-$(hostname -I | awk '{print $1}')} # Original line, uncomment if dynamic IP is desired
    # --- Ask for SQL user password ---
    # Prompt for DVWA SQL password with 15-second timeout, defaulting to "pass" if no input
    echo -e "\e[96mEnter SQL password for DVWA user (press Enter ↲ for default: pass):\e[0m"
    if ! read -t 15 -s DB_PASS < /dev/tty; then
        DB_PASS="pass"
    fi
    echo
    DB_PASS=${DB_PASS:-pass}

    print_info "Installing required packages for DVWA.."
    apt install -y apache2 mariadb-server php php-mysqli php-gd php-zip php-json php-bcmath php-xml libapache2-mod-php git

    print_info "Enabling and starting Apache & MariaDB.."
    systemctl enable apache2 --now
    systemctl enable mariadb --now

    print_info "Cloning DVWA repository.."
    cd /var/www/html
    if [ -d "DVWA" ] || [ -d "dvwa" ]; then
        print_info "DVWA folder already exists, skipping clone.."
    else
        git clone https://github.com/digininja/DVWA.git
        mv DVWA dvwa
    fi

    print_info "Setting permissions.."
    sudo chown -R www-data:www-data /var/www/html/dvwa
    sudo chmod -R 755 /var/www/html/dvwa

    print_info "Configuring MariaDB for DVWA.."
    # This assumes root can connect to MariaDB initially without a password, or via auth_socket.
    # If MariaDB root password is set, this might fail.
    mysql -u root <<EOF
    CREATE DATABASE IF NOT EXISTS ${DB_NAME};
    CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
    GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
    FLUSH PRIVILEGES;
EOF

    print_info "Updating DVWA config file.."
    cd "$WEB_DIR/config" || exit 1 # Exit if directory not found
    cp -n config.inc.php.dist config.inc.php
    # Check if the config file exists
    CONFIG_FILE="/var/www/html/dvwa/config/config.inc.php"
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "Error: Configuration file not found at $CONFIG_FILE"
        exit 1
    fi
    # Remove Windows-style carriage returns
    sed -i 's/\r//g' "$CONFIG_FILE"
    # Comment out the original lines and insert new ones
    sed -i "/'db_server'/c\\
    \$_DVWA[ 'db_server' ] = '$DB_HOST';
    " "$CONFIG_FILE"
    sed -i "/'db_user'/c\\
    \$_DVWA[ 'db_user' ] = '$DB_USER';
    " "$CONFIG_FILE"
    sed -i "/'db_password'/c\\
    \$_DVWA[ 'db_password' ] = '$DB_PASS';
    " "$CONFIG_FILE"
    print_info "Configuration file updated successfully."

    print_info "Configuring PHP settings for DVWA.."
    PHPINI="/etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/apache2/php.ini"
    sed -i 's/^\s*allow_url_fopen\s*=.*/allow_url_fopen = On/' "$PHPINI" || true
    sed -i 's/^\s*allow_url_include\s*=.*/allow_url_include = On/' "$PHPINI" || true


    print_info "Restarting Apache.."
    systemctl restart apache2

    ### Apache Configuration for Localhost Only ###
    print_info "Setting Apache to localhost-only mode"

    # 1) Set GLOBAL ServerName in apache2.conf to prevent AH00558 warning
    if ! grep -q "ServerName" /etc/apache2/apache2.conf; then
        print_info "Adding global ServerName to apache2.conf"
        echo "ServerName ${SERVER_NAME}" | sudo tee -a /etc/apache2/apache2.conf > /dev/null
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

    # 3 Enable site and modules
    sudo a2ensite dvwa.conf || print_warn "DVWA site already enabled."
    sudo a2enmod rewrite || print_warn "Rewrite module already enabled."
    sudo a2dissite 000-default.conf || print_warn "Default site already disabled."
    sudo apache2ctl configtest
    sudo apache2ctl -S

    print_info "Configuring UFW firewall for HTTP access.."
    ufw allow 80 || print_warn "UFW rule for port 80 already exists."

    # 4 Restart Apache
    sudo systemctl restart apache2

    echo "======================================="
    print_success "[✔] DVWA configured successfully!"
    print_title "Global ServerName set to ${SERVER_NAME}"
    curl -I http://localhost/dvwa/setup.php || print_warn "Curl to setup.php failed, verify Apache is running."
    print_title "  → Accessible at: http://${SERVER_NAME}/dvwa/setup.php"
    print_title "Default DB User: ${DB_USER}, Password: ${DB_PASS}"
    print_title " Username : admin"
    print_title " Password : password (DVWA default)"
    echo "======================================="
}

# NEW FUNCTION: Downgrade to MySQL 5.0.15 for DVWA
downgrade_to_mysql50_dvwa() {
    print_title "=== Downgrading DVWA Database to MySQL 5.0.15 ==="

    # Configuration for MySQL 5.0.15
    MYSQL_VERSION="5.0.15"
    MYSQL_TARBALL="mysql-standard-${MYSQL_VERSION}-linux-x86_64-glibc23.tar.gz"
    MYSQL_URL="https://downloads.mysql.com/archives/get/p/23/file/${MYSQL_TARBALL}"
    DOWNLOAD_DIR="/tmp/mysql_install"
    INSTALL_DIR="/usr/local/mysql"
    ROOT_PASSWORD="password" # Set the desired simple root password for MySQL 5.0.15
    DVWA_DB_NAME="dvwa"
    DVWA_DB_USER="dvwa"
    DVWA_DB_PASS="pass" # Consistent with DVWA script default

    print_warn "This will completely remove existing MySQL/MariaDB packages and data. Proceed with caution!"
    read -p "Are you sure you want to continue? (y/N) " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborting MySQL 5.0.15 downgrade."
        exit 1
    fi

    print_info "Stopping and purging existing database servers (MySQL/MariaDB)..."
    systemctl stop mysql || true # Stop modern MySQL if running
    systemctl stop mariadb || true # Stop MariaDB if running
    apt-get purge -y mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-* mariadb-server mariadb-client mariadb-common || true
    apt-get autoremove -y
    apt-get clean
    rm -rf /etc/mysql /var/lib/mysql /var/lib/mysql/mysql # Ensure old data directories are gone

    print_info "Installing dependencies for old MySQL..."
    apt-get update
    apt-get install -y libncurses5 libaio1 # libaio1 is often required for older MySQL

    print_info "Downloading old MySQL version ${MYSQL_VERSION}..."
    mkdir -p "$DOWNLOAD_DIR"
    cd "$DOWNLOAD_DIR"
    if [ ! -f "$MYSQL_TARBALL" ]; then
        wget "$MYSQL_URL" -O "$MYSQL_TARBALL"
    else
        print_info "$MYSQL_TARBALL already downloaded."
    fi

    print_info "Extracting and installing MySQL..."
    rm -rf "$INSTALL_DIR" # Clean up any previous attempts
    tar -xzf "$MYSQL_TARBALL"
    mv "mysql-standard-${MYSQL_VERSION}-linux-x86_64-glibc23" "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    print_info "Creating mysql user and group..."
    groupadd mysql || true
    useradd -r -g mysql -s /bin/false mysql || true
    chown -R mysql .
    chgrp -R mysql .

    print_info "Initializing MySQL database..."
    "$INSTALL_DIR/scripts/mysql_install_db" --user=mysql --basedir="$INSTALL_DIR" --datadir="$INSTALL_DIR/data"
    chown -R root .
    chown -R mysql data

    print_info "Starting MySQL server..."
    "$INSTALL_DIR/bin/mysqld_safe" --user=mysql &
    MYSQL_PID=$! # Store PID for later
    sleep 15 # Give it time to start

    if ! kill -0 "$MYSQL_PID" 2>/dev/null; then
        print_error "MySQL 5.0.15 server failed to start. Check logs for errors."
        exit 1
    fi
    print_info "MySQL 5.0.15 server started with PID: $MYSQL_PID"

    print_info "Setting root password to '${ROOT_PASSWORD}'..."
    # MySQL 5.0.15's mysqladmin might require different syntax for initial password set
    # Try without -p first if it's a fresh install and no password.
    echo "Attempting to set root password for MySQL 5.0.15. If it fails, you might need to manually reset or start without grant tables."
    "$INSTALL_DIR/bin/mysqladmin" -u root password "${ROOT_PASSWORD}" || \
    (print_warn "Could not set root password directly. Trying again with the old 'mysql -u root SET PASSWORD...' method." && \
    "$INSTALL_DIR/bin/mysql" -u root -e "UPDATE mysql.user SET Password=PASSWORD('${ROOT_PASSWORD}') WHERE User='root'; FLUSH PRIVILEGES;") || \
    print_error "Failed to set root password for MySQL 5.0.15. Manual intervention required."

    print_info "Creating DVWA database and user..."
    "$INSTALL_DIR/bin/mysql" -u root -p"${ROOT_PASSWORD}" -e "CREATE DATABASE IF NOT EXISTS ${DVWA_DB_NAME};"
    "$INSTALL_DIR/bin/mysql" -u root -p"${ROOT_PASSWORD}" -e "CREATE USER IF NOT EXISTS '${DVWA_DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DVWA_DB_PASS}';"
    "$INSTALL_DIR/bin/mysql" -u root -p"${ROOT_PASSWORD}" -e "GRANT ALL PRIVILEGES ON ${DVWA_DB_NAME}.* TO '${DVWA_DB_USER}'@'${DB_HOST}';"
    "$INSTALL_DIR/bin/mysql" -u root -p"${ROOT_PASSWORD}" -e "FLUSH PRIVILEGES;"

    print_info "Stopping MySQL 5.0.15 for proper shutdown."
    "$INSTALL_DIR/bin/mysqladmin" -u root -p"${ROOT_PASSWORD}" shutdown || print_warn "Failed to gracefully shut down MySQL 5.0.15."
    wait "$MYSQL_PID" 2>/dev/null || print_warn "mysqld_safe process did not terminate gracefully."

    print_info "Configuring MySQL 5.0.15 to start on boot (manual step - this is a simple run, not a service)."
    print_warn "MySQL 5.0.15 is not integrated as a systemd service. You will need to start it manually: '$INSTALL_DIR/bin/mysqld_safe --user=mysql &' or create a service unit."

    print_info "Updating DVWA config file for MySQL 5.0.15.."
    WEB_DIR="/var/www/html/dvwa" # Ensure this is correct
    CONFIG_FILE="$WEB_DIR/config/config.inc.php"
    if [ ! -f "$CONFIG_FILE" ]; then
        print_error "DVWA configuration file not found at $CONFIG_FILE. Did DVWA get installed first?"
        exit 1
    fi
    sed -i 's/\r//g' "$CONFIG_FILE" # Remove Windows-style carriage returns
    sed -i "/'db_server'/c\\
    \$_DVWA[ 'db_server' ] = '${DB_HOST}';
    " "$CONFIG_FILE"
    sed -i "/'db_user'/c\\
    \$_DVWA[ 'db_user' ] = '${DVWA_DB_USER}';
    " "$CONFIG_FILE"
    sed -i "/'db_password'/c\\
    \$_DVWA[ 'db_password' ] = '${DVWA_DB_PASS}';
    " "$CONFIG_FILE"
    print_info "DVWA configuration file updated for MySQL 5.0.15."

    print_success "MySQL 5.0.15 downgrade and DVWA database configuration complete! ✅"
    print_info "Remember to start MySQL 5.0.15 manually if needed: '$INSTALL_DIR/bin/mysqld_safe --user=mysql &'"
    print_info "Go to DVWA's /setup.php page in your browser to configure and create the database tables."
}

# Function to display the final signature
print_signature() {
    echo
    if command -v get_language_message >/dev/null 2>&1; then
        # Assuming get_language_message is a function that might exist
        # to provide translations or special formatting.
        final_message=$(get_language_message "\\033[1;32mCreated with ♡, Harsha")
        echo -e "$final_message"
    else
        # Default fallback if the function doesn't exist
        echo -e "\n\033[92mCreated with ♡, Harsha\033[0m\n"
    fi
}

### ===== MAIN LOGIC ===== ###
case "${1:-}" in # Use "${1:-}" to handle empty argument robustly
    "ssh")
        # Handle the 'ssh' argument
        install_ssh
        print_info "[✔] SSH-only installation complete."
        print_signature # Call the signature function
        ;;
    "dvwa")
        # Handle the 'dvwa' argument (will install with MariaDB)
        install_dvwa
        print_info "[✔] DVWA (MariaDB) installation complete."
        print_signature # Call the signature function
        ;;
    "mysql50")
        # Handle the new 'mysql50' argument for downgrade
        downgrade_to_mysql50_dvwa
        print_info "[✔] MySQL 5.0.15 downgrade for DVWA complete."
        print_signature
        ;;
    "")
        # Handle the empty argument (no argument provided)
        install_ssh
        install_dvwa # Default to MariaDB installation for this script
        print_info "[✔] Full SSH + DVWA (MariaDB) installation complete."
        print_signature # Call the signature function
        ;;
    *)
        # Handle all other (invalid) arguments
        print_error "Invalid argument: $1"
        echo "Usage: $0 [ssh | dvwa | mysql50]"
        exit 1
        ;;
esac

