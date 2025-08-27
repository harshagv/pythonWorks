#!/bin/bash
set -e

RESET="\033[0m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
PINK="\033[1;35m"

print_info() {
  echo -e "${CYAN}[INFO]${RESET} $1"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]${RESET} $1"
}

print_error() {
  echo -e "\033[1;31m[ERROR]\033[0m $1"
}

print_title() {
  echo -e "\n${PINK}=== $1 ===${RESET}\n"
}

install_ssh() {
  print_title "Installing OpenSSH Server"
  apt update && apt upgrade -y
  apt install -y openssh-server ufw net-tools curl

  sed -i 's/^#Port 22/Port 22/' /etc/ssh/sshd_config
  sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config
  sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

  ufw allow 22
  ufw --force enable
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
  print_title "Installing DVWA + NGINX + PHP-FPM + NAXSI"

  DB_NAME="dvwa"
  DB_USER="dvwa"
  DB_PASS="pass"
  DB_HOST="localhost"
  WEB_DIR="/var/www/html/dvwa"
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
DeniedUrl "/naxsi";

CheckRule "\$SQL >= 8" BLOCK;
CheckRule "\$RFI >= 8" BLOCK;
CheckRule "\$TRAVERSAL >= 4" BLOCK;
CheckRule "\$EVADE >= 4" BLOCK;
CheckRule "\$XSS >= 8" BLOCK;
EOF

  # Setup Nginx site config for DVWA
  cat >/etc/nginx/sites-available/dvwa <<EOF
server {
  listen 80;
  server_name ${SERVER_NAME};
  root ${WEB_DIR};
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
    fastcgi_pass unix:/run/php/php-fpm.sock;
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
  chown -R www-data:www-data "${WEB_DIR}"
  find "${WEB_DIR}" -type d -exec chmod 755 {} \;
  find "${WEB_DIR}" -type f -exec chmod 644 {} \;

  # Create 403 error page if missing
  if [ ! -f /usr/share/nginx/html/403.html ]; then
    mkdir -p /usr/share/nginx/html
    echo "<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>" > /usr/share/nginx/html/403.html
  fi

  # Enable and start services
  systemctl enable mariadb nginx php-fpm --now

  mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
EOF

  # Setup PHP config for security and ensure PHP-FPM service matches socket
  PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
  PHP_INI="/etc/php/${PHP_VER}/fpm/php.ini"

  sed -i 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "${PHP_INI}"

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

case "$1" in
  ssh)
    install_ssh
    ;;
  dvwa)
    install_pcre2
    install_dvwa_naxsi
    ;;
  *)
    install_ssh
    install_pcre2
    install_dvwa_naxsi
    ;;
esac
