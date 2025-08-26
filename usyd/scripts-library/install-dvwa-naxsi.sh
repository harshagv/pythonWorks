#!/bin/bash
# DVWA & SSH Auto Install Script for Ubuntu using NGINX + PHP-FPM + NAXSI WAF
# Usage:
#   sudo bash install-dvwa.sh          # Install SSH + DVWA
#   sudo bash install-dvwa.sh ssh      # Install SSH only
#   sudo bash install-dvwa.sh dvwa     # Install DVWA only

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

install_ssh() {
  print_title "=== STEP 1: Install and Configure OpenSSH Server ==="
  echo "Updating system.."
  apt update && apt upgrade -y

  echo "Installing OpenSSH server and essentials.."
  apt install -y openssh-server net-tools curl ufw

  echo "Configuring SSH.."
  SSHD_CONFIG="/etc/ssh/sshd_config"
  sed -i 's/^#Port 22/Port 22/' "$SSHD_CONFIG"
  sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' "$SSHD_CONFIG"
  sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' "$SSHD_CONFIG"

  echo "Configuring UFW firewall for SSH and ICMP.."
  ufw status || true
  ufw enable
  ufw allow 22
  ufw allow icmp

  echo "Restarting SSH.."
  systemctl restart ssh

  print_success "OpenSSH server installed successfully!"
}

install_dvwa_naxsi() {
  print_title "=== STEP 2: DVWA with NGINX + PHP-FPM + NAXSI WAF ==="

  DB_NAME="dvwa"
  DB_USER="dvwa"
  DB_HOST="localhost"
  WEB_DIR="/var/www/html/dvwa"
  SERVER_NAME="localhost"

  echo -e "\e[96mEnter SQL password for DVWA user (press Enter ↲ for default: pass):\e[0m"
  read -s DB_PASS < /dev/tty
  echo
  DB_PASS=${DB_PASS:-pass}

  echo "Installing required packages: nginx, mariadb-server, php-fpm and extensions, git.."
  apt install -y nginx mariadb-server php-fpm php-mysql php-gd php-zip php-json php-bcmath php-xml git build-essential libpcre3 libpcre3-dev libssl-dev zlib1g-dev

  # Install Naxsi by compiling
  print_info "Downloading and compiling Naxsi module for NGINX.."
  cd /usr/local/src
  if [ ! -d "naxsi" ]; then
    git clone https://github.com/nbs-system/naxsi.git
  else
    print_info "Naxsi repo exists, skipping clone"
  fi

  cd naxsi/naxsi_src
  make
  make install

  # Download nginx source to compile with Naxsi
  cd /usr/local/src
  nginx_version=$(nginx -v 2>&1 | grep -o '[0-9\.]*' || echo "1.18.0")
  if [ ! -d "nginx-$nginx_version" ]; then
    wget http://nginx.org/download/nginx-${nginx_version}.tar.gz
    tar -xzvf nginx-${nginx_version}.tar.gz
  fi

  cd nginx-${nginx_version}

  # Recompile nginx with naxsi module - This exact step depends on your environment,
  # Alternatively use pre-built dynamic module or install from OS repository if available.
  ./configure --with-compat --add-dynamic-module=/usr/local/src/naxsi/naxsi_src
  make modules
  cp objs/ngx_http_naxsi_module.so /etc/nginx/modules

  # Configure nginx to load naxsi module
  if ! grep -q "naxsi_module" /etc/nginx/nginx.conf; then
    sed -i '1i load_module modules/ngx_http_naxsi_module.so;' /etc/nginx/nginx.conf
  fi

  # Download and configure naxsi config
  mkdir -p /etc/nginx/naxsi
  cp /usr/local/src/naxsi/naxsi_config/naxsi_core.rules /etc/nginx/naxsi/
  cp /usr/local/src/naxsi/naxsi_config/naxsi_basic.rules /etc/nginx/naxsi/

  # Create nginx server block for DVWA with PHP-FPM + NAXSI in learning mode
  cat <<EOF > /etc/nginx/sites-available/dvwa
server {
  listen 80;
  server_name $SERVER_NAME;

  root $WEB_DIR;
  index index.php index.html index.htm;

  location / {
    try_files \$uri \$uri/ /index.php?\$args;
  }

  location ~ \.php$ {
      include snippets/fastcgi-php.conf;
      fastcgi_pass unix:/run/php/php-fpm.sock;
      fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
      include fastcgi_params;
  }

  location /naxsi_rules {
      include /etc/nginx/naxsi/naxsi_core.rules;
      include /etc/nginx/naxsi/naxsi_basic.rules;
      SecRulesEnabled;
      LearningMode;
  }

  error_page 403 /403.html;
  location = /403.html {
      root /usr/share/nginx/html;
      internal;
  }
}
EOF

  ln -sf /etc/nginx/sites-available/dvwa /etc/nginx/sites-enabled/dvwa
  rm -f /etc/nginx/sites-enabled/default

  print_info "Downloading DVWA source code.."
  cd /var/www/html
  if [ -d "DVWA" ] || [ -d "dvwa" ]; then
      echo "DVWA directory exists, skipping clone.."
  else
      git clone https://github.com/digininja/DVWA.git
      mv DVWA dvwa
  fi

  print_info "Setting ownership and permissions.."
  chown -R www-data:www-data $WEB_DIR
  chmod -R 755 $WEB_DIR

  print_info "Configuring MariaDB.."
  systemctl enable mariadb --now

  mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
EOF

  print_info "Adjusting PHP settings as needed.."
  PHPINI="/etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/fpm/php.ini"
  sed -i 's/^;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' "$PHPINI"

  print_info "Restarting PHP-FPM and NGINX.."
  systemctl enable php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-fpm --now
  systemctl enable nginx --now

  print_success "[✔] DVWA configured successfully with NGINX + PHP-FPM + NAXSI!"
  print_title "Access DVWA at http://${SERVER_NAME}/dvwa/setup.php"
  print_title "Default DB User: ${DB_USER}, Password: ${DB_PASS}"
  print_title "DVWA default: Username 'admin', Password 'password'"
}

### ===== MAIN LOGIC ===== ###
case "$1" in
    "ssh")
        install_ssh
        print_info "[✔] SSH-only installation complete."
        ;;
    "dvwa")
        install_dvwa_naxsi
        print_info "[✔] DVWA + with NGINX + PHP-FPM + NAXSI WAF installation complete."
        ;;
    "")
        install_ssh
        install_dvwa_naxsi
        print_info "[✔] Full SSH + DVWA + with NGINX + PHP-FPM + NAXSI WAF installation complete."
        ;;
    *)
        echo "Usage: $0 [ssh|dvwa]"
        exit 1
        ;;
esac
