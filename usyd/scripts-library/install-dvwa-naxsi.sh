#!/bin/bash
# DVWA & SSH Auto Install Script for Ubuntu using NGINX + PHP-FPM + NAXSI WAF
# Usage:
#   sudo bash install-dvwa.sh          # Install SSH + DVWA + NGINX + PHP-FPM + NAXSI WAF
#   sudo bash install-dvwa.sh ssh      # Install SSH only
#   sudo bash install-dvwa.sh dvwa     # Install DVWA + NGINX + PHP-FPM + NAXSI WAF only
# ------------------------------------------------------------------------------
# TESTING NAXSI WAF: To confirm NAXSI is working and blocking attacks, run:
#
#   # Blocked XSS test (should Blocked by NAXSI):
#   curl 'http://localhost/?q=><script>alert(0)</script>'
#   <OR> Open this in browser: "http://localhost/?q=><script>alert('XSS alert! Message stored');</script> Hello, this is my stored message"
#
#   # Blocked SQLi test (should Blocked by NAXSI):
#   curl "http://localhost/?q=1%27%20or%20%221%22=%221"
#   <OR> Open this in browser: "http://localhost/?q=1\' or \"1\"=\"1"
#
#   # To see NAXSI logs and details, run this in another terminal:
#   sudo tail -f /var/log/nginx/error.log
#
#   # To switch NAXSI to LearningMode, edit /etc/nginx/naxsi/naxsi.rules:
#   # Add 'LearningMode;' to the top, then reload nginx:
#   sudo systemctl reload nginx
#   sudo systemctl restart nginx
#   # Now both curl tests will not be blocked, but attacks will still be logged.
# ------------------------------------------------------------------------------

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

install_ssh() {
  print_title "Installing OpenSSH Server"
  apt update && apt upgrade -y
  apt install -y openssh-server ufw net-tools curl

  echo "Configuring SSH.."
  SSHD_CONFIG="/etc/ssh/sshd_config"
  sed -i 's/^#Port 22/Port 22/' "$SSHD_CONFIG"
  sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' "$SSHD_CONFIG"
  sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$SSHD_CONFIG"

  ufw allow 22
  ufw --force enable

  echo "Restarting SSH.."
  systemctl restart ssh

  print_success "OpenSSH server installed successfully!"
}

install_pcre2() {
  print_title "Installing PCRE2 from official GitHub releases"

  PCRE2_VER="10.45"
  PCRE2_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VER}/pcre2-${PCRE2_VER}.tar.gz"

  cd /usr/local/src

  if [ ! -d "pcre2-${PCRE2_VER}" ]; then
    print_info "Downloading PCRE2 ${PCRE2_VER} source..."
    wget -q --show-progress "${PCRE2_URL}" -O pcre2-${PCRE2_VER}.tar.gz

    tar -xzf pcre2-${PCRE2_VER}.tar.gz
    cd pcre2-${PCRE2_VER}
    ./configure
    make
    make install
    ldconfig
  else
    print_info "PCRE2 ${PCRE2_VER} already installed"
  fi
}

install_dvwa_naxsi() {
  print_title "STEP 2: Installing DVWA with NGINX + PHP-FPM + NAXSI WAF"

  DB_NAME="dvwa"
  DB_USER="dvwa"
  DB_PASS="pass"
  DB_HOST="localhost"
  WEB_DIR="/var/www/html/dvwa"
  HTML_ROOT_DIR="/var/www/html"
  SERVER_NAME="localhost"

  print_info "Installing dependencies..."
  apt install -y nginx mariadb-server php-fpm php-mysql php-gd php-zip php-json php-bcmath php-xml git build-essential libssl-dev zlib1g-dev libpcre2-dev unzip

  NGINX_VER=$(nginx -v 2>&1 | grep -o '[0-9.]*')

  cd /usr/local/src

  if [ ! -d "nginx-${NGINX_VER}" ]; then
    print_info "Downloading nginx-${NGINX_VER} source..."
    wget "http://nginx.org/download/nginx-${NGINX_VER}.tar.gz"
    tar -xzf nginx-${NGINX_VER}.tar.gz
  fi

  if [ ! -d "/usr/local/src/naxsi" ]; then
    print_info "Cloning Naxsi with recursive submodules..."
    git clone --recurse-submodules https://github.com/wargio/naxsi.git /usr/local/src/naxsi
  fi

  TARGET_USER=$(logname 2>/dev/null || echo $SUDO_USER || echo $(whoami))
  print_info "Adjusting ownership of /usr/local/src/naxsi to $TARGET_USER"
  sudo chown -R "$TARGET_USER:$TARGET_USER" /usr/local/src/naxsi

  cd /usr/local/src/naxsi
  git pull
  git submodule sync --recursive
  git submodule update --init --recursive
  git submodule foreach --recursive git pull origin main || true

  if [ -f "/usr/local/src/naxsi/naxsi_rules/naxsi_core.rules" ]; then
    mkdir -p /etc/nginx/naxsi
    cp /usr/local/src/naxsi/naxsi_rules/naxsi_core.rules /etc/nginx/naxsi/
  else
    print_error "Naxsi core rules file not found in /usr/local/src/naxsi/naxsi_rules."
    exit 1
  fi

  cd /usr/local/src/nginx-${NGINX_VER}
  print_info "Configuring NGINX with Naxsi dynamic module..."
  ./configure --with-compat --add-dynamic-module=../naxsi/naxsi_src --with-http_ssl_module

  print_info "Building Naxsi dynamic module..."
  make modules

  MODULES_DIR=$(nginx -V 2>&1 | grep -- '--modules-path' | sed -e "s/.*=//")
  if [ ! -d "$MODULES_DIR" ]; then
    mkdir -p "$MODULES_DIR"
  fi

  cp objs/ngx_http_naxsi_module.so "$MODULES_DIR/"

  # Copy module from build to /usr/lib/nginx/modules (required by nginx.conf)
  mkdir -p /usr/lib/nginx/modules
  cp objs/ngx_http_naxsi_module.so /usr/lib/nginx/modules/

  if ! grep -q "load_module modules/ngx_http_naxsi_module.so;" /etc/nginx/nginx.conf; then
    sed -i '1i load_module modules/ngx_http_naxsi_module.so;' /etc/nginx/nginx.conf
  fi

  # Ensure core rules included in nginx.conf http block
  if ! grep -q "include /etc/nginx/naxsi/naxsi_core.rules;" /etc/nginx/nginx.conf; then
    sed -i '/http {/a \    include /etc/nginx/naxsi/naxsi_core.rules;' /etc/nginx/nginx.conf
  fi

  # Create NAXSI local rules file with basic config and attack checks
  cat >/etc/nginx/naxsi/naxsi.rules <<EOF
SecRulesEnabled;
#LearningMode;
DeniedUrl "/naxsi";
CheckRule "\$SQL >= 8" BLOCK;
CheckRule "\$RFI >= 8" BLOCK;
CheckRule "\$TRAVERSAL >= 4" BLOCK;
CheckRule "\$EVADE >= 4" BLOCK;
CheckRule "\$XSS >= 8" BLOCK;
EOF

  PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
  PHP_FPM_SOCK="/run/php/php${PHP_VER}-fpm.sock"

  # Setup Nginx site config for DVWA
  cat >/etc/nginx/sites-available/dvwa <<EOF
server {
  listen 80;
  server_name ${SERVER_NAME};
  root ${HTML_ROOT_DIR};
  index index.php index.html;

  location /naxsi {
    internal;
    root /usr/share/nginx/html;
    try_files /naxsi.html =404;
  }

  location / {
    try_files \$uri \$uri/ /index.php?\$args;
    include /etc/nginx/naxsi/naxsi.rules;
  }

  location ~ \\.php\$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:${PHP_FPM_SOCK};
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    include fastcgi_params;
  }

  error_page 403 /403.html;
  location = /403.html {
    root /usr/share/nginx/html;
    internal;
  }
}
EOF

  # Link site config and remove default site
  ln -sf /etc/nginx/sites-available/dvwa /etc/nginx/sites-enabled/
  rm -f /etc/nginx/sites-enabled/default

  cd /var/www/html
  if [ ! -d dvwa ]; then
    print_info "Cloning DVWA repo..."
    git clone https://github.com/digininja/DVWA.git dvwa
  else
    print_info "DVWA directory exists, skipping clone."
  fi

  # Set ownership and permissions
  chown -R www-data:www-data "${HTML_ROOT_DIR}"
  find "${HTML_ROOT_DIR}" -type d -exec chmod 755 {} \;
  find "${HTML_ROOT_DIR}" -type f -exec chmod 644 {} \;

  # Create 403 error page if missing
  if [ ! -f /usr/share/nginx/html/403.html ]; then
    mkdir -p /usr/share/nginx/html
    echo "<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>" > /usr/share/nginx/html/403.html
  fi

  # Enable and start services
  systemctl enable mariadb nginx --now

  echo -e "\e[96mEnter SQL password for DVWA user (press Enter ↲ for default: pass):\e[0m"
  read -s DB_PASS < /dev/tty
  echo
  DB_PASS=${DB_PASS:-pass}

  mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
EOF

  # DVWA config file setup
  print_info "Updating DVWA config file.."
  cd "$WEB_DIR/config"
  cp -n config.inc.php.dist config.inc.php
  CONFIG_FILE="$WEB_DIR/config/config.inc.php"
  if [ ! -f "$CONFIG_FILE" ]; then
      print_error "Error: Configuration file not found at $CONFIG_FILE"
      exit 1
  fi
  sed -i 's/\r//g' "$CONFIG_FILE"
  sed -i "/'db_server'/c\\\$_DVWA[ 'db_server' ] = '$DB_HOST';" "$CONFIG_FILE"
  sed -i "/'db_user'/c\\\$_DVWA[ 'db_user' ] = '$DB_USER';" "$CONFIG_FILE"
  sed -i "/'db_password'/c\\\$_DVWA[ 'db_password' ] = '$DB_PASS';" "$CONFIG_FILE"
  print_info "Configuration file updated successfully."

  # ... nginx sites, DB provisioning & PHP setup ...
  # Setup PHP config (for NGINX FPM, not Apache):
  print_info "Configuring PHP settings for DVWA.."
  # Setup PHP config for security and ensure PHP-FPM service matches socket
  PHPINI="/etc/php/${PHP_VER}/fpm/php.ini"
  sed -i 's/^\s*allow_url_fopen\s*=.*/allow_url_fopen = On/' "$PHPINI"
  sed -i 's/^\s*allow_url_include\s*=.*/allow_url_include = On/' "$PHPINI"
  print_info "PHP settings updated (allow_url_fopen, allow_url_include)"

  sed -i 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "${PHPINI}"

  if systemctl list-units --type=service | grep -q "php${PHP_VER}-fpm.service"; then
    systemctl enable php${PHP_VER}-fpm --now
    systemctl restart php${PHP_VER}-fpm
  else
    print_error "PHP-FPM service php${PHP_VER}-fpm not found!"
    exit 1
  fi

  print_success "DVWA + NGINX + PHP-FPM + NAXSI installed successfully"
  print_info "Access DVWA setup at: http://${SERVER_NAME}/dvwa/setup.php"
  print_info "Default credentials: admin / password"
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
case "$1" in
    "ssh")
        # Handle the 'ssh' argument
        install_ssh
        print_info "[✔] SSH-only installation complete."
        print_signature # Call the signature function
        ;;
    "dvwa")
        # Handle the 'dvwa' argument
        install_pcre2
        install_dvwa_naxsi
        print_info "[✔] DVWA + NAXSI installation complete."
        print_signature # Call the signature function
        ;;
    "")
        # Handle the empty argument (no argument provided)
        install_ssh
        install_pcre2
        install_dvwa_naxsi
        print_info "[✔] Full SSH + DVWA installation complete."
        print_signature # Call the signature function
        ;;
    *)
        # Handle all other (invalid) arguments
        echo "Usage: $0 [ssh]"
        exit 1
        ;;
esac

