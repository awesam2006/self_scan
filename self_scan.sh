#!/bin/bash

# ==================================================================
# 	Self_Scan - Bash-Based Security Assessment Tool Project
# ==================================================================

VERSION="1.0"
REPORT_DIR="${SELFSCAN_REPORT_DIR:-reports}"
FINDINGS_FILE="$REPORT_DIR/findings.txt"
SCAN_REPORT="$REPORT_DIR/scan.txt"
SUMMARY_REPORT="$REPORT_DIR/summary.txt"
LOG_FILE="$REPORT_DIR/selfscan.log"
# ==========================================================
#			Functions
# ==========================================================

# Displays the usage message when no target is provided
usage() {
    echo "Usage:"
    echo "  $0 <target>"
    echo "  $0 <target1> <target2> ..."
    echo "  $0 <targets.txt>"
}

# ==========================================================
# 		BONUS #4 - Help and Version
# ==========================================================

# Displays detailed help and usage information
show_help() {
    cat << EOF
Usage:
  $0 <target>
  $0 <target1> <target2> ...
  $0 <targets.txt>

Description:
  Performs an automated security assessment of one or more targets.

Target modes:
  <target>       Scan a single IP address or hostname.
  <target1> ...  Scan multiple targets supplied directly in the terminal.
  <targets.txt>  Scan multiple targets listed in a file, one per line.

Options:
  -h, --help     Show this help message.
  -v, --version  Show program version.

Examples:
  $0 192.168.34.129
  $0 192.168.34.129 192.168.34.130 192.168.34.131
  $0 targets.txt

Reports:
  Single target:
    reports/scan.txt
    reports/findings.txt
    reports/summary.txt
    reports/report.html

  Multiple targets:
    reports/<target>/scan.txt
    reports/<target>/findings.txt
    reports/<target>/summary.txt
    reports/<target>/report.html
EOF
}
# Displays the current tool version
show_version() {
    echo "SelfScan Version $VERSION"
}
# ==========================================================
#                  Utility Functions
# ==========================================================

# Formats scan duration into hours, minutes, and seconds
format_time() {
    local seconds="$1"
    local hours=$((seconds / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local remaining_seconds=$((seconds % 60))

    if (( hours > 0 )); then
        echo "${hours}h ${minutes}m ${remaining_seconds}s"
    elif (( minutes > 0 )); then
        echo "${minutes}m ${remaining_seconds}s"
    else
        echo "${remaining_seconds}s"
    fi
}

# ==========================================================
#		 Error Handling - Dependency Check
# ==========================================================

# Checks whether required tools are installed
check_dependencies() {
	# RustScan is required for fast TCP port discovery
    if ! command -v rustscan >/dev/null 2>&1; then
    	echo "[-] rustscan is not installed"
    	return 1
    fi
	# Nmap is required for service/version detection and NSE
    if ! command -v nmap >/dev/null 2>&1; then
        echo "[-] nmap is not installed"
        return 1
    fi
  	 # Assume standard OS utilities are available
   	 PING_AVAILABLE=true
    	 GETENT_AVAILABLE=true
    	 IP_AVAILABLE=true
	
	# ping is used for host availability checking
    if ! command -v ping >/dev/null 2>&1; then
        echo "[!] ping is not installed - host availability check will be skipped"
        PING_AVAILABLE=false

    fi

    	# getent is used for hostname and IP resolution
    if ! command -v getent >/dev/null 2>&1; then
        echo "[!] getent is not installed - hostname resolution may be skipped"
        GETENT_AVAILABLE=false

    fi

    	# ip is used to collect basic network information
    if ! command -v ip >/dev/null 2>&1; then
        echo "[!] ip command is not installed - network information may be skipped"
        IP_AVAILABLE=false

    fi


    return 0
}

# ==========================================================
# 			Argument Handling
# ==========================================================

# Stops execution if no target was provided
if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

# Handles optional command-line arguments (The Flags)
case "$1" in
    --help|-h)
        show_help
        exit 0
        ;;

    --version|-v)
        show_version
        exit 0
        ;;
esac

# ==========================================================
#                  Multiple Target Support
# ==========================================================

# Multiple targets can be supplied either:
#   ./self_scan.sh targets.txt
#   ./self_scan.sh TARGET1 TARGET2 TARGET3

if [[ $# -gt 1 ]] || [[ -f "$1" ]]; then

    OVERALL_RC=0
    TARGET_COUNT=0

    # ------------------------------------------------------
    # Build target list
    # ------------------------------------------------------

    if [[ -f "$1" ]]; then
        TARGET_LIST="$1"

        echo "[+] Multiple-target mode enabled"
        echo "[+] Target list: $TARGET_LIST"
        echo

        TARGETS=()

        while IFS= read -r TARGET_LINE || [[ -n "$TARGET_LINE" ]]; do

            # Remove comments
            TARGET_LINE="${TARGET_LINE%%#*}"

            # Trim leading/trailing whitespace
            TARGET_LINE="$(printf '%s' "$TARGET_LINE" |
                sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

            # Skip empty lines
            [[ -z "$TARGET_LINE" ]] && continue

            TARGETS+=("$TARGET_LINE")

        done < "$TARGET_LIST"

    else
        echo "[+] Multiple-target mode enabled"
        echo "[+] Targets supplied from command line"
        echo

        TARGETS=("$@")
    fi

    # ------------------------------------------------------
    # Scan each target separately
    # ------------------------------------------------------

    for TARGET_ITEM in "${TARGETS[@]}"; do

        ((TARGET_COUNT++))

        # Make a filesystem-safe directory name
        SAFE_TARGET_NAME="$(printf '%s' "$TARGET_ITEM" |
            sed 's/[^A-Za-z0-9._-]/_/g')"

        echo "=========================================="
        echo "       Target $TARGET_COUNT: $TARGET_ITEM"
        echo "=========================================="

        SELFSCAN_REPORT_DIR="$REPORT_DIR/$SAFE_TARGET_NAME" \
            "$0" "$TARGET_ITEM"

        TARGET_RC=$?

        if [[ $TARGET_RC -ne 0 ]]; then
            OVERALL_RC=1
            echo "[!] Target failed: $TARGET_ITEM"
        else
            echo "[+] Target completed: $TARGET_ITEM"
        fi

        echo
    done

    # ------------------------------------------------------
    # Validate target count
    # ------------------------------------------------------

    if [[ $TARGET_COUNT -eq 0 ]]; then
        echo "[!] No valid targets were supplied"
        exit 1
    fi

    echo "=========================================="
    echo "[+] Multiple-target scan completed"
    echo "[+] Targets processed: $TARGET_COUNT"
    echo "=========================================="

    exit "$OVERALL_RC"
fi

TARGET="$1"
SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')

# ==========================================================
#		Error Handling - Dependency Check
# ==========================================================

# Stops execution if a required dependency is missing
if ! check_dependencies; then
    exit 1
fi
# Initializes execution logging
mkdir -p "$REPORT_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1
# ==========================================================
#             REQUIREMENT 4.1 - Reconnaissance
# ==========================================================

# Checks whether the target is reachable
check_host_availability() {
    if [[ "$PING_AVAILABLE" == false ]]; then
        return 0
    fi

    if ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
        echo "[+] Target is reachable"
        return 0
    else
        echo "[-] Target is unreachable"
        return 1
    fi
}
# Validates that a value is a valid IPv4 address
is_valid_ipv4() {
    local ip="$1"
    local octet
    local octets

    IFS='.' read -r -a octets <<< "$ip"

    # IPv4 must contain exactly four octets
    if [[ ${#octets[@]} -ne 4 ]]; then
        return 1
    fi

    # Each octet must contain only digits and be between 0 and 255
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]]; then
            return 1
        fi

        if (( 10#$octet > 255 )); then
            return 1
        fi
    done

    return 0
}


# Gets and validates the target IP address
get_target_ip() {

    # If the target contains only digits and dots,
    # treat it as an IPv4 address and validate it.
    if [[ "$TARGET" =~ ^[0-9.]+$ ]]; then

        if ! is_valid_ipv4 "$TARGET"; then
            echo "[-] Invalid IPv4 address: $TARGET"
            return 1
        fi

        TARGET_IP="$TARGET"

    else

        # Resolve a hostname to an IPv4 address
        if [[ "$GETENT_AVAILABLE" == false ]]; then
            echo "[-] getent is not installed - hostname resolution skipped"
            return 1
        fi

        TARGET_IP=$(getent ahostsv4 "$TARGET" | awk 'NR==1 {print $1}')

        if [[ -z "$TARGET_IP" ]]; then
            echo "[-] Could not resolve target IP"
            return 1
        fi
    fi

    echo "[+] Target IP: $TARGET_IP"
    return 0
}

# Gets the target hostname
get_target_hostname() {
    if [[ "$GETENT_AVAILABLE" == false ]]; then
        echo "[*] Target hostname: Resolution unavailable"
        return 0
    fi

    TARGET_HOSTNAME=$(getent hosts "$TARGET_IP" | awk 'NR==1 {print $2}')

    if [[ -n "$TARGET_HOSTNAME" ]]; then
        echo "[+] Target hostname: $TARGET_HOSTNAME"
    else
        echo "[*] Target hostname: Not resolved"
    fi
}

# Collects basic network information (I made it like this because ip route was so bad where it displayed the info in one line and none important ones)
get_network_info() {
	 if [[ "$IP_AVAILABLE" == false ]]; then
        echo "[-] ip command is not installed - network information skipped"
        return 0
  	 fi

   	 ROUTE_INFO=$(ip route get "$TARGET_IP" 2>/dev/null)

   	 if [[ -z "$ROUTE_INFO" ]]; then
       		 echo "[-] Could not determine network information"
       		 return 0
   	 fi

   	 INTERFACE=$(echo "$ROUTE_INFO" | awk '
        	{
            		for (i = 1; i <= NF; i++)
                	if ($i == "dev")
                    	print $(i+1)
        	}
    	')

    SOURCE_IP=$(echo "$ROUTE_INFO" | awk '
        {
            for (i = 1; i <= NF; i++)
                if ($i == "src")
                    print $(i+1)
        }
    ')

    GATEWAY=$(echo "$ROUTE_INFO" | awk '
        {
            for (i = 1; i <= NF; i++)
                if ($i == "via")
                    print $(i+1)
        }
    ')

    echo "[*] Basic network information:"
    echo "    Interface: $INTERFACE"
    echo "    Source IP: $SOURCE_IP"

    if [[ -n "$GATEWAY" ]]; then
        echo "    Gateway:   $GATEWAY"
    else
        echo "    Gateway:   Direct connection"
    fi
}

# ==========================================================
#       REQUIREMENT 4.2 - Port & Service Enumeration
# ==========================================================

# Runs RustScan in greppable mode to discover open TCP ports
run_rustscan() {
    echo "[*] Starting RustScan..."

    RUSTSCAN_OUTPUT=$(rustscan -a "$TARGET_IP" --ulimit 5000 -g 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "[-] RustScan scan failed"
        return 1
    fi

    echo "[+] RustScan scan completed"
    return 0
}

# Extracts open TCP ports discovered by RustScan
parse_rustscan_ports() {
    OPEN_PORTS=$(echo "$RUSTSCAN_OUTPUT" |
        sed -n 's/.*\[\(.*\)\]/\1/p')

    if [[ -z "$OPEN_PORTS" ]]; then
        echo "[-] No open TCP ports found"
        return 1
    fi

    echo "[+] Open TCP ports: $OPEN_PORTS"
    return 0
}

# Counts the number of open TCP ports
count_open_ports() {
    OPEN_PORT_COUNT=$(echo "$OPEN_PORTS" | tr ',' '\n' | wc -l)

    echo "[+] Open TCP ports found: $OPEN_PORT_COUNT"
}

# Runs Nmap service/version detection on discovered ports
run_nmap_service_scan() {
    echo "[*] Starting Nmap service/version detection..."

    SCAN_START=$SECONDS

    NMAP_OUTPUT=$(nmap -n -Pn -sV --version-light -p "$OPEN_PORTS" "$TARGET_IP" 2>&1)

    SCAN_TIME=$((SECONDS - SCAN_START))

    if [[ $? -ne 0 ]]; then
        echo "[-] Nmap service scan failed"
        return 1
    fi

    echo "[+] Nmap service scan completed"
    echo "[*] Scan time: $(format_time "$SCAN_TIME")"

    return 0
}
# Extracts detected services and full versions from Nmap results
parse_services() {
    echo
    echo "[*] Detected services:"

    echo "$NMAP_OUTPUT" |
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {

        VERSION = ""

        # Collect everything after the service name as the version
        for (i = 4; i <= NF; i++) {
            if (VERSION == "")
                VERSION = $i
            else
                VERSION = VERSION " " $i
        }

        printf "    %-6s %-15s %s\n", $1, $3, VERSION
    }'
}
# Runs the appropriate module based on the detected service
run_service_modules() {

    echo
    echo "=========================================================="
    echo "       REQUIREMENT 4.3 - Automated Enumeration"
    echo "=========================================================="

    while IFS='|' read -r PORT SERVICE; do

        PORT="${PORT%/tcp}"

        case "$SERVICE" in

            ftp|ccproxy-ftp)
                echo "[+] FTP detected on port $PORT"
                ./modules/ftp.sh "$TARGET_IP" "$PORT" "$FINDINGS_FILE"
                ;;

            ssh)
                echo "[+] SSH detected on port $PORT"
                ./modules/ssh.sh "$TARGET_IP" "$PORT" "$FINDINGS_FILE"
                ;;

            netbios-ssn|microsoft-ds)
                echo "[+] SMB detected on port $PORT"
                ./modules/smb.sh "$TARGET_IP" "$PORT" "$FINDINGS_FILE"
                ;;

            smtp)
                echo "[+] SMTP detected on port $PORT"
                ./modules/smtp.sh "$TARGET_IP" "$PORT" "$FINDINGS_FILE"
                ;;

            domain)
                echo "[+] DNS detected on port $PORT"
                ./modules/dns.sh "$TARGET_IP" "$PORT" "$FINDINGS_FILE"
                ;;

            http|ssl/http|https|ssl/https)
                echo "[+] HTTP detected on port $PORT"
                ./modules/http.sh "$TARGET_IP" "$PORT" "$FINDINGS_FILE"
                ;;

            *)
                echo "[*] No automated 4.3 module for $SERVICE on port $PORT"
                ;;

        esac

    done < <(
        echo "$NMAP_OUTPUT" |
        awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {
            print $1 "|" $3
        }'
    )
}
# ==========================================================
#             REQUIREMENT 4.4 - Security Checks
# ==========================================================

# Initializes the findings report for the current scan
initialize_findings() {
    mkdir -p "$REPORT_DIR"

    {
        echo "SelfScan Security Findings"
        echo "=========================================="
        echo "Target: $TARGET"
        echo "Target IP: $TARGET_IP"
        echo "Target Hostname: ${TARGET_HOSTNAME:-Not resolved}"
        echo "Scan Date: $SCAN_DATE"
        echo "Open TCP Ports: $OPEN_PORTS"
        echo "Open TCP Port Count: $OPEN_PORT_COUNT"
        echo

        echo "Detected Services:"
        echo "$NMAP_OUTPUT" |
        awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {

            VERSION = ""

            for (i = 4; i <= NF; i++) {
                if (VERSION == "")
                    VERSION = $i
                else
                    VERSION = VERSION " " $i
            }

            printf "    %-6s %-15s %s\n", $1, $3, VERSION
        }'

        echo
    } > "$FINDINGS_FILE"
}
# Adds an explanation for each finding's risk level
add_risk_explanations() {

    local TEMP_FILE

    TEMP_FILE=$(mktemp)

    awk '
        /^Risk: High$/ {
            print
            print "Risk Explanation: This issue may expose the target to significant unauthorized access, data exposure, or service compromise."
            next
        }

        /^Risk: Medium$/ {
            print
            print "Risk Explanation: This issue may increase the attack surface or assist further compromise when combined with other weaknesses."
            next
        }

        /^Risk: Low$/ {
            print
            print "Risk Explanation: This issue primarily exposes information or weakens a security control and may support further attack activity."
            next
        }

        { print }
    ' "$FINDINGS_FILE" > "$TEMP_FILE"

    if [[ $? -ne 0 ]]; then
        echo "[-] Failed to add risk explanations"
        rm -f "$TEMP_FILE"
        return 1
    fi

    mv "$TEMP_FILE" "$FINDINGS_FILE"

    echo "[+] Risk explanations added to findings"
    return 0
}


# Generates the detailed scan report
generate_scan_report() {

    mkdir -p "$REPORT_DIR"

    {
        echo "SelfScan Scan Report"
        echo "=========================================="
        echo "Target: $TARGET"
        echo "Target IP: $TARGET_IP"
        echo "Target Hostname: ${TARGET_HOSTNAME:-Not resolved}"
        echo "Scan Date: $SCAN_DATE"
        echo

        echo "Basic Network Information:"
        echo "    Interface: ${INTERFACE:-Not available}"
        echo "    Source IP: ${SOURCE_IP:-Not available}"

        if [[ -n "$GATEWAY" ]]; then
            echo "    Gateway:   $GATEWAY"
        else
            echo "    Gateway:   Direct connection"
        fi

        echo
        echo "Open TCP Ports:"
        echo "    $OPEN_PORTS"
        echo "    Total: $OPEN_PORT_COUNT"
        echo

        echo "Detected Services:"
        echo "$NMAP_OUTPUT" |
        awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {

            VERSION = ""

            for (i = 4; i <= NF; i++) {
                if (VERSION == "")
                    VERSION = $i
                else
                    VERSION = VERSION " " $i
            }

            printf "    %-6s %-15s %s\n", $1, $3, VERSION
        }'

        echo
        echo "Findings"
        echo "=========================================="

        sed -n '/^Finding:/,$p' "$FINDINGS_FILE"

    } > "$SCAN_REPORT"

    if [[ $? -ne 0 ]]; then
        echo "[-] Failed to generate scan report"
        return 1
    fi

    echo "[+] Scan report generated: $SCAN_REPORT"
    return 0
}


# Generates the concise security summary report
generate_summary_report() {

    mkdir -p "$REPORT_DIR"

    TOTAL_FINDINGS=$(grep -c "^Finding:" "$FINDINGS_FILE" 2>/dev/null || true)
    HIGH_FINDINGS=$(grep -c "^Risk: High$" "$FINDINGS_FILE" 2>/dev/null || true)
    MEDIUM_FINDINGS=$(grep -c "^Risk: Medium$" "$FINDINGS_FILE" 2>/dev/null || true)
    LOW_FINDINGS=$(grep -c "^Risk: Low$" "$FINDINGS_FILE" 2>/dev/null || true)

    {
        echo "SelfScan Security Summary"
        echo "=========================================="
        echo "Target: $TARGET"
        echo "Target IP: $TARGET_IP"
        echo "Target Hostname: ${TARGET_HOSTNAME:-Not resolved}"
        echo "Scan Date: $SCAN_DATE"
        echo

        echo "Open TCP Ports:"
        echo "    $OPEN_PORTS"
        echo "    Total: $OPEN_PORT_COUNT"
        echo

        echo "Detected Services:"
        echo "$NMAP_OUTPUT" |
        awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" {

            VERSION = ""

            for (i = 4; i <= NF; i++) {
                if (VERSION == "")
                    VERSION = $i
                else
                    VERSION = VERSION " " $i
            }

            printf "    %-6s %-15s %s\n", $1, $3, VERSION
        }'

        echo
        echo "Finding Summary"
        echo "=========================================="
        echo "Total Findings: $TOTAL_FINDINGS"
        echo "High Risk:      $HIGH_FINDINGS"
        echo "Medium Risk:    $MEDIUM_FINDINGS"
        echo "Low Risk:       $LOW_FINDINGS"

        echo
        echo "Findings, Evidence, Risk & Recommendations"
        echo "=========================================="

        awk '
            /^Finding:/ {
                if (finding != "")
                    print ""

                finding=$0
                port=""
                risk=""
                risk_explanation=""
                evidence=""
                recommendation=""

                next
            }

            /^Port:/ {
                port=$0
                next
            }

            /^Risk:/ {
                risk=$0
                next
            }

            /^Risk Explanation:/ {
                risk_explanation=$0
                next
            }

            /^Evidence:/ {
                evidence=$0
                next
            }

            /^Recommendation:/ {
                recommendation=$0

                print finding
                print port
                print risk
                print risk_explanation
                print evidence
                print recommendation

                next
            }
        ' "$FINDINGS_FILE"

        echo
        echo "Detailed Report: $FINDINGS_FILE"

    } > "$SUMMARY_REPORT"

    if [[ $? -ne 0 ]]; then
        echo "[-] Failed to generate summary report"
        return 1
    fi

    echo "[+] Summary report generated: $SUMMARY_REPORT"
    return 0
}

# ==========================================================
#                BONUS #2 - HTML Report
# ==========================================================

# Escapes special HTML characters in report files
html_escape_file() {
    sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        "$1"
}

# Generates an HTML version of the security reports
generate_html_report() {

    local HTML_REPORT="$REPORT_DIR/report.html"

    mkdir -p "$REPORT_DIR"

    {
        echo '<!DOCTYPE html>'
        echo '<html lang="en">'
        echo '<head>'
        echo '<meta charset="UTF-8">'
        echo '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        echo '<title>SelfScan Security Assessment</title>'

        cat << 'EOF'
<style>
body {
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    color: #222;
    margin: 0;
    padding: 30px;
}

.container {
    max-width: 1100px;
    margin: auto;
}

h1 {
    margin-bottom: 5px;
}

.section {
    background: white;
    padding: 20px;
    margin-top: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}

pre {
    white-space: pre-wrap;
    word-wrap: break-word;
    background: #f8f9fa;
    padding: 15px;
    border-radius: 6px;
    overflow-x: auto;
}

.footer {
    margin-top: 30px;
    font-size: 13px;
    color: #666;
}
</style>
EOF

        echo '</head>'
        echo '<body>'
        echo '<div class="container">'

        echo '<h1>SelfScan Security Assessment</h1>'
        echo "<p>Target: $TARGET</p>"

        echo '<div class="section">'
        echo '<h2>Summary</h2>'
        echo '<pre>'
        html_escape_file "$SUMMARY_REPORT"
        echo '</pre>'
        echo '</div>'

        echo '<div class="section">'
        echo '<h2>Findings</h2>'
        echo '<pre>'
        html_escape_file "$FINDINGS_FILE"
        echo '</pre>'
        echo '</div>'

        echo '<div class="section">'
        echo '<h2>Scan Report</h2>'
        echo '<pre>'
        html_escape_file "$SCAN_REPORT"
        echo '</pre>'
        echo '</div>'

        echo '<div class="footer">'
        echo 'Generated by SelfScan Security Assessment Tool'
        echo '</div>'

        echo '</div>'
        echo '</body>'
        echo '</html>'

    } > "$HTML_REPORT"

    if [[ $? -ne 0 ]]; then
        echo "[-] Failed to generate HTML report"
        return 1
    fi

    echo "[+] HTML report generated: $HTML_REPORT"
    return 0
}

# ==========================================================
# 			Banner
# ==========================================================

# Displays the tool name, version, and target
echo "=========================================="
echo "       SelfScan Security Assessment"
echo "=========================================="
echo "Version: $VERSION"
echo "Target:  $TARGET"
echo
# ==========================================================
#             REQUIREMENT 4.1 - Reconnaissance(call)
# ==========================================================

get_target_ip || exit 1
check_host_availability || exit 1
get_target_hostname
get_network_info
# ==========================================================
#       REQUIREMENT 4.2 - Port & Service Enumeration(call)
# ==========================================================

run_rustscan || exit 1
parse_rustscan_ports || exit 1
count_open_ports
run_nmap_service_scan || exit 1
parse_services
# ==========================================================
#       REQUIREMENT 4.4 - Security Checks(call)
# ==========================================================

initialize_findings

# ==========================================================
#       REQUIREMENT 4.3 - Automated Enumeration(call)
# ==========================================================
run_service_modules

# ==========================================================
#             REQUIREMENT 4.4 - Security Checks(call)
# ==========================================================
add_risk_explanations || exit 1

# ==========================================================
#             REQUIREMENT 4.5 - Report Generation(call)
# ==========================================================

generate_scan_report || exit 1
generate_summary_report || exit 1
# ==========================================================
#                BONUS #2 - HTML Report
# ==========================================================

generate_html_report || exit 1 
echo
echo "=========================================================="
echo "                 Scan Completed"
echo "=========================================================="
echo "[+] Findings report: $FINDINGS_FILE"
echo "[+] Scan report:     $SCAN_REPORT"
echo "[+] Summary report:  $SUMMARY_REPORT"
echo "[+] HTML report:     $REPORT_DIR/report.html"
echo "[+] Execution log:   $LOG_FILE"
