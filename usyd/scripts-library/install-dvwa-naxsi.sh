#!/bin/bash
# DVWA & SSH Auto Install Script for Ubuntu using NGINX + PHP-FPM + NAXSI WAF
# Usage:
#   sudo bash install-dvwa.sh          # Install SSH + DVWA + NGINX + PHP-FPM + NAXSI WAF
#   sudo bash install-dvwa.sh ssh      # Install SSH only
#   sudo bash install-dvwa.sh dvwa     # Install DVWA + NGINX + PHP-FPM + NAXSI WAF only
# ------------------------------------------------------------------------------
# 
#   # Create PHP config file as info.php and view it in browser
#   echo "Helloo! <?php phpinfo(); ?>" | tee /var/www/html/info.php
#
#   Open this in browser: "http://localhost/info.php"
#
#
# TESTING NAXSI WAF: To confirm NAXSI is working and blocking attacks, run:
#
#   # Blocked XSS test (should be blocked by NAXSI):
#   curl 'http://localhost/?q=><script>alert(0)</script>'
#   <OR>
#   Open this in browser: "http://localhost/?q=><script>alert('XSS alert! Message stored');</script>Hello, this is my stored message"
#
#   # Blocked SQL Injection test (should be blocked by NAXSI):
#   curl "http://localhost/?q=1'%20or%20'1'%3D'1'%20%23"
#   <OR>
#   curl "http://localhost/?q=1%27%20or%20%271%27%3D%271%27%20%23"
#   <OR>
#   Open this in browser: "http://localhost/?q=1' or '1'='1' #"
#
# For testing SQL injection on DVWA, use the parameter payload:
#
#   1' or '1'='1' #
#
# This payload works on DVWA to bypass input filters and trigger SQL injection.
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

# Genereate the script logs
LOGFILE="$(pwd)/dvwa-naxsi-installer-$(date +"%Y%m%d-%H%M%S").log"
exec > >(tee -a "$LOGFILE") 2>&1

# Stricter Error Handling
set -euo pipefail
IFS=$'\n\t'

# === Signal-safe Cleanup =====
cleanup() {
  local exit_code=$?
  echo -e "\n[INFO] Cleaning up before exit. Exit code: $exit_code"
  # Add any specific cleanup commands here if needed
}
handle_interrupt() {
  echo -e "\n[ERROR] Script interrupted by user (SIGINT)" >&2
  exit 130
}
trap cleanup EXIT
trap handle_interrupt INT

### === COLOR CONSTANTS === ###
RESET="\033[0m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
PINK="\033[1;35m"
CYAN="\033[1;36m"

### === PRINT FUNCTIONS === ###
print_info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
print_warn() { echo -e "${YELLOW}[WARNING]${RESET} $1"; }
print_error() { echo -e "${RED}[ERROR]${RESET}❌ $1"; }
print_title() { echo -e "\n${PINK}=== $1 ===${RESET}\n"; }

install_ssh() {
  print_title "Installing OpenSSH Server"
  apt update && apt upgrade -y
  apt install -y openssh-server ufw net-tools curl build-essential pkg-config

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

# install_pcre2() {
#   print_title "Installing PCRE2 from official GitHub releases"

#   PCRE2_VER="10.45"
#   PCRE2_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VER}/pcre2-${PCRE2_VER}.tar.gz"

#   cd /usr/local/src

#   if [ ! -d "pcre2-${PCRE2_VER}" ]; then
#     print_info "Downloading PCRE2 ${PCRE2_VER} source..."
#     wget -q --show-progress "${PCRE2_URL}" -O pcre2-${PCRE2_VER}.tar.gz

#     tar -xzf pcre2-${PCRE2_VER}.tar.gz
#     cd pcre2-${PCRE2_VER}
#     ./configure
#     make
#     make install
#     ldconfig
#   else
#     print_info "PCRE2 ${PCRE2_VER} already installed"
#   fi
# }

install_dvwa_naxsi() {
  print_title "STEP 2: Installing DVWA with NGINX + PHP-FPM + NAXSI WAF"

  DB_NAME="dvwa"
  DB_USER="dvwa"
  DB_PASS="pass"
  DB_HOST="localhost"
  WEB_DIR="/var/www/html/dvwa"
  HTML_ROOT_DIR="/var/www/html"
  SERVER_NAME="localhost"

  # Autodetect PHP version, fallback to 8.3 if not found
  # This needs to be done early to use in the PCRE2 patch
  PHP_VER="$(ls /etc/php/ | grep -E '^[0-9]+\.[0-9]+$' | sort -nr | head -n1)" || true
  PHP_VER="${PHP_VER:-8.3}"

  # --- PCRE2 Conflict Resolution Patch (Full version, moved to before apt install) ---
  print_info "Checking for PCRE2 manual installation conflicts that might affect PHP-FPM ${PHP_VER}..."
  conflict_found=false
  # List to check commonly installed PCRE2 libs in /usr/local/lib
  PCRE2_LIBS=(
    "libpcre2-8.so.0"
    "libpcre2-8.so.0.12.1" # Example specific version that might be manually compiled
    "libpcre2-8.so.0.14.0" # Added based on your `ls -la` output
    "libpcre2-8.so"        # Generic symlink
    "libpcre2-16.so.0"
    "libpcre2-16.so.0.12.1"
    "libpcre2-16.so"
    "libpcre2-posix.so.0"
    "libpcre2-posix.so.0.0.0"
    "libpcre2-posix.so"
  )

  # First, check what php-fpm is currently linking to (if it exists)
  if command -v php-fpm"${PHP_VER}" &>/dev/null; then
      print_info "Current php-fpm${PHP_VER} PCRE2 linkage before potential fix:"
      ldd /usr/sbin/php-fpm"${PHP_VER}" | grep pcre || print_info "  (No direct pcre linkage found or php-fpm not fully installed yet)"
  fi

  for lib_file in "${PCRE2_LIBS[@]}"; do
    if [ -f "/usr/local/lib/$lib_file" ]; then
      print_warn "Found potentially conflicting manual PCRE2 library: /usr/local/lib/$lib_file. Renaming to disable."
      sudo mv "/usr/local/lib/$lib_file" "/usr/local/lib/${lib_file}.bak" || print_error "Failed to rename $lib_file."
      conflict_found=true
    fi
  done

  if [ "${conflict_found}" = "true" ]; then
    print_info "PCRE2 conflict(s) detected and renamed. Updating linker cache..."
    if sudo ldconfig; then
      print_success "Linker cache updated successfully."
    else
      print_error "Failed to update linker cache (ldconfig). This might cause further issues. Please check manually."
      # Not exiting here immediately, as it might still proceed if the main conflict was moved.
    fi

    # Attempt to restart php-fpm service if it was already installed but failed
    print_info "Attempting to restart php-fpm${PHP_VER} service after PCRE fix..."
    systemctl daemon-reload || true # Reload systemd units
    systemctl restart php"${PHP_VER}"-fpm.service || true # Try restarting, might still fail if config is bad

    print_info "Verifying PHP-FPM ${PHP_VER} configuration after PCRE fix..."
    if sudo php-fpm"${PHP_VER}" -tt; then
      print_success "PHP-FPM ${PHP_VER} config test passed after PCRE fix."
    else
      print_error "PHP-FPM ${PHP_VER} config test failed even after PCRE fix. Manual intervention is required."
      print_error "Check 'systemctl status php${PHP_VER}-fpm.service' and 'journalctl -xeu php${PHP_VER}-fpm.service' for details."
      # Do not exit here, let apt try to reconfigure. dpkg might fix it.
    fi

    # Further optional verification
    print_info "Checking PHP modules and linked PCRE library for php-fpm${PHP_VER}..."
    if php"${PHP_VER}" -m | grep -q pcre; then
        print_success "PCRE module is detected by php${PHP_VER}."
    else
        print_warn "PCRE module not detected by php${PHP_VER} after fix. This might be an issue."
    fi
    if ldd /usr/sbin/php-fpm"${PHP_VER}" | grep -q "libpcre2"; then
        print_success "php-fpm${PHP_VER} is dynamically linking to libpcre2. Details:"
        ldd /usr/sbin/php-fpm"${PHP_VER}" | grep pcre
    else
        print_warn "php-fpm${PHP_VER} is NOT linking to libpcre2 after fix, or grep command failed. This might be an issue."
    fi
  else
    print_info "No conflicting manual PCRE2 libraries found in /usr/local/lib, no fix needed at this stage."
  fi
  # --- End of PCRE2 Conflict Resolution Patch ---

  print_info "Installing dependencies..."
  apt update # Ensure apt cache is up-to-date before installing
  apt install -y nginx mariadb-server php-fpm php-mysql php-gd php-zip php-json php-bcmath php-xml git build-essential libssl-dev zlib1g-dev libpcre2-dev unzip

  # Re-check PHP_VER after apt install, in case a new PHP version was installed
  PHP_VER="$(ls /etc/php/ | grep -E '^[0-9]+\.[0-9]+$' | sort -nr | head -n1)" || true
  PHP_VER="${PHP_VER:-8.3}" # Fallback if no PHP is found
  PHP_FPM_SOCK="/run/php/php${PHP_VER}-fpm.sock"

  # NGINX compilation for NAXSI
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
  git pull || true # Pull updates, ignore if fails (e.g., detached HEAD)
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
  print_info "Cleaning NGINX source directory before configuring..."
  make clean || true # Clean up any previous build artifacts

  print_info "Configuring NGINX with Naxsi dynamic module..."
  # REMOVED: --with-pcre=/usr as it causes issues with system-installed libpcre2-dev.
  # NGINX's configure will automatically find libpcre2-dev if installed via apt.
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

  # Verify file was created and contains required lines
  NAXSI_RULES_FILE="/etc/nginx/naxsi/naxsi.rules"

  if [ ! -f "$NAXSI_RULES_FILE" ]; then
    print_error "Error: $NAXSI_RULES_FILE not created!"
    exit 1
  fi

  # Check each expected line exists in file (strict grep match)
  if ! grep -Fxq "SecRulesEnabled;" "$NAXSI_RULES_FILE" ||
    ! grep -Fxq "#LearningMode;" "$NAXSI_RULES_FILE" ||
    ! grep -Fxq 'DeniedUrl "/naxsi";' "$NAXSI_RULES_FILE" ||
    ! grep -Fxq 'CheckRule "$SQL >= 8" BLOCK;' "$NAXSI_RULES_FILE" ||
    ! grep -Fxq 'CheckRule "$RFI >= 8" BLOCK;' "$NAXSI_RULES_FILE" ||
    ! grep -Fxq 'CheckRule "$TRAVERSAL >= 4" BLOCK;' "$NAXSI_RULES_FILE" ||
    ! grep -Fxq 'CheckRule "$EVADE >= 4" BLOCK;' "$NAXSI_RULES_FILE" ||
    ! grep -Fxq 'CheckRule "$XSS >= 8" BLOCK;' "$NAXSI_RULES_FILE"; then
    print_error "Error: $NAXSI_RULES_FILE missing required rules!"
    exit 1
  fi

  print_info "Created NAXSI Rules at /etc/nginx/naxsi/naxsi.rules"

  # Create Naxsi blocked page if missing
  if [ ! -f /usr/share/nginx/html/naxsi.html ]; then
    mkdir -p /usr/share/nginx/html
    cat > /usr/share/nginx/html/naxsi.html <<EOL
<html>
<head><title>Request Blocked</title></head>
<body>
  <h1>Request Blocked by NAXSI Web Application Firewall</h1>
  <p>Your request was rejected due to security policy violation.</p>
</body>
</html>
EOL
    print_info "Created NAXSI blocked page at /usr/share/nginx/html/naxsi.html"
  fi

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
  rm -f /etc/nginx/sites-enabled/default || true # Use || true to avoid error if file doesn't exist

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
    echo "<html><body><h1>403 Forbidden</h1><p>Access denied! NAXSI running in LearningMode</p></body></html>" > /usr/share/nginx/html/403.html
  fi

  # if systemctl list-unit-files --type=service | grep -q "^php${PHP_VER}-fpm.service"; then
  #   if ! systemctl is-enabled --quiet php${PHP_VER}-fpm.service; then
  #     systemctl enable php${PHP_VER}-fpm.service
  #   fi
  # else
  #   print_error "PHP-FPM service php${PHP_VER}-fpm.service not found!"
  #   exit 1
  # fi

  # # Manual check for PCRE2 conflicts break PHP 8.3-FPM in Windows Host > Ubuntu VM
  # print_info "Checking for PCRE2 manual installation conflicts..."

  # # List to check commonly installed PCRE2 libs in /usr/local/lib
  # for lib in libpcre2-8.so.0 libpcre2-posix.so.0 libpcre2-16.so.0; do
  #   if [ -f "/usr/local/lib/$lib" ]; then
  #     print_warn "Found manual PCRE2 library /usr/local/lib/$lib - renaming to disable"
  #     sudo mv "/usr/local/lib/$lib" "/usr/local/lib/${lib}.bak"
  #     conflict_found=true
  #   fi
  # done

  # if [ "${conflict_found:-false} " = "true" ]; then
  #   print_info "Updating linker cache..."
  #   sudo ldconfig

  #   print_info "Verifying PHP-FPM ${PHP_VER} status after PCRE fix..."

  #   if sudo php-fpm${PHP_VER} -tt; then
  #     print_success "PHP-FPM config test passed."
  #   else
  #     print_error "PHP-FPM config test failed after PCRE fix - please check manually."
  #     exit 1
  #   fi
  # else
  #   print_info "No manual PCRE2 libraries found in /usr/local/lib, no fix needed."
  # fi

  # --- PCRE2 Conflict Resolution Patch ---
  print_info "Checking for PCRE2 manual installation conflicts that might affect PHP-FPM ${PHP_VER}..."
  conflict_found=false
  # List to check commonly installed PCRE2 libs in /usr/local/lib
  PCRE2_LIBS=(
    "libpcre2-8.so.0"
    "libpcre2-8.so.0.12.1" # Example specific version that might be manually compiled
    "libpcre2-8.so"        # Generic symlink
    "libpcre2-16.so.0"
    "libpcre2-16.so.0.12.1"
    "libpcre2-16.so"
    "libpcre2-posix.so.0"
    "libpcre2-posix.so.0.0.0"
    "libpcre2-posix.so"
  )

  for lib_file in "${PCRE2_LIBS[@]}"; do
    if [ -f "/usr/local/lib/$lib_file" ]; then
      print_warn "Found potentially conflicting manual PCRE2 library: /usr/local/lib/$lib_file. Renaming to disable."
      sudo mv "/usr/local/lib/$lib_file" "/usr/local/lib/${lib_file}.bak" || print_error "Failed to rename $lib_file."
      conflict_found=true
    fi
  done

  if [ "${conflict_found}" = "true" ]; then
    print_info "PCRE2 conflict(s) detected and renamed. Updating linker cache..."
    if sudo ldconfig; then
      print_success "Linker cache updated successfully."
    else
      print_error "Failed to update linker cache (ldconfig). This might cause further issues. Please check manually."
      # Not exiting here immediately, as it might still proceed if the main conflict was moved.
    fi

    print_info "Verifying PHP-FPM ${PHP_VER} configuration after PCRE fix..."
    if sudo php-fpm"${PHP_VER}" -tt; then
      print_success "PHP-FPM ${PHP_VER} config test passed after PCRE fix."
    else
      print_error "PHP-FPM ${PHP_VER} config test failed even after PCRE fix. Manual intervention is required."
      print_error "Check 'systemctl status php${PHP_VER}-fpm.service' and 'journalctl -xeu php${PHP_VER}-fpm.service' for details."
      exit 1 # Exit if FPM config test still fails
    fi

    # Further optional verification
    print_info "Checking PHP modules and linked PCRE library for php-fpm${PHP_VER}..."
    if php"${PHP_VER}" -m | grep -q pcre; then
        print_info "PCRE module is detected by php${PHP_VER}."
    else
        print_warn "PCRE module not detected by php${PHP_VER} after fix. This might be an issue."
    fi
    if ldd /usr/sbin/php-fpm"${PHP_VER}" | grep -q "libpcre2"; then
        print_info "php-fpm${PHP_VER} is dynamically linking to libpcre2. Details:"
        ldd /usr/sbin/php-fpm"${PHP_VER}" | grep pcre
    else
        print_warn "php-fpm${PHP_VER} is NOT linking to libpcre2 after fix, or grep command failed. This might be an issue."
    fi
  else
    print_info "No conflicting manual PCRE2 libraries found in /usr/local/lib, no fix needed at this stage."
  fi
  # --- End of PCRE2 Conflict Resolution Patch ---

  # Enable and start services
  systemctl enable php${PHP_VER}-fpm.service mariadb nginx --now

  # Prompt for DVWA SQL password with 15-second timeout, defaulting to "pass" if no input
  echo -e "\e[96mEnter SQL password for DVWA user (press Enter ↲ for default: pass):\e[0m"
  if ! read -t 15 -s DB_PASS < /dev/tty; then
    DB_PASS="pass"
  fi
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

  # Setup PHP config (for NGINX FPM, not Apache):
  print_info "Configuring PHP settings for DVWA.."
  PHPINI="/etc/php/${PHP_VER}/fpm/php.ini"
  sed -i 's/^\s*allow_url_fopen\s*=.*/allow_url_fopen = On/' "$PHPINI" || true
  sed -i 's/^\s*allow_url_include\s*=.*/allow_url_include = On/' "$PHPINI" || true
  print_info "PHP settings updated (allow_url_fopen, allow_url_include)"

  sed -i 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "${PHPINI}" || true

  # Final restart of nginx and php${PHP_VER}-fpm service after all configurations
  print_info "Performing final restart of PHP-FPM and NGINX services..."
  systemctl restart php${PHP_VER}-fpm nginx

  print_success "DVWA + NGINX + PHP-FPM + NAXSI installed successfully ✅"
  print_info "Access DVWA setup at: http://${SERVER_NAME}/dvwa/setup.php"
  print_info "Default credentials: admin / password"
}

# Function to display the final signature
print_signature() {
    echo
    if command -v get_language_message >/dev/null 2>&1; then
        # Assuming get_language_message is a function that might exist
        # to provide translations or special formatting.
        final_message=$(get_language_message "\033[1;32mCreated with ♡, Harsha")
        echo -e "$final_message"
    else
        # Default fallback if the function doesn't exist
        echo -e "\n\033[92mCreated with ♡, Harsha\033[0m\n"
    fi
}

### === MAIN LOGIC === ###
case "${1:-}" in
    "ssh")
        # Handle the 'ssh' argument
        install_ssh
        print_info "[✔] SSH-only installation complete."
        print_signature # Call the signature function
        ;;
    "dvwa")
        # Handle the 'dvwa' argument
        # REMOVED: install_pcre2 is the root cause of the PHP-FPM PCRE2 conflict and NGINX build error.
        # install_pcre2
        install_dvwa_naxsi
        print_info "[✔] DVWA + NAXSI installation complete."
        print_signature # Call the signature function
        ;;
    "")
        # Handle the empty argument (no argument provided)
        install_ssh
        # REMOVED: install_pcre2 is the root cause of the PHP-FPM PCRE2 conflict and NGINX build error.
        # install_pcre2
        install_dvwa_naxsi
        print_info "[✔] Full SSH + DVWA installation complete."
        print_signature # Call the signature function
        ;;
    *)
        # Handle all other (invalid) arguments
        echo "Usage: $0 [ssh | dvwa]"
        exit 1
        ;;
esac