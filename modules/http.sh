#!/bin/bash

# ==========================================================
# REQUIREMENT 4.3 - Automated Enumeration
# REQUIREMENT 4.4 - Security Checks
# BONUS #3 - Deep Service-Specific Enumeration
# BONUS #6 - Modular Architecture
# ==========================================================

TARGET="$1"
PORT="$2"
FINDINGS_FILE="${3:-reports/findings.txt}"

# Writes a structured security finding to the findings file
write_finding() {
    local title="$1"
    local evidence="$2"
    local risk="$3"
    local recommendation="$4"

    {
        echo "=========================================="
        echo "Finding: $title"
        echo "Target: $TARGET"
        echo "Port: $PORT"
        echo "Risk: $risk"
        echo "Evidence: $evidence"
        echo "Recommendation: $recommendation"
        echo
    } >> "$FINDINGS_FILE"
}

# Runs HTTP enumeration and checks the results for security findings
run_http_enum() {

    echo
    echo "[*] Starting HTTP enumeration on port $PORT..."

    HTTP_OUTPUT=$(nmap -Pn -n -sV --version-light -p "$PORT" \
        --script http-title,http-headers,http-robots.txt,http-methods,http-enum \
        "$TARGET" 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "[-] HTTP enumeration failed"
        return 1
    fi

    echo "$HTTP_OUTPUT"

    if echo "$HTTP_OUTPUT" | grep -qE \
        "http-title:|http-headers:|http-robots\.txt:|http-methods:|http-enum:"; then

        echo "[+] HTTP enumeration completed on port $PORT"

    else

        echo "[!] No HTTP enumeration information returned on port $PORT"
    fi

    # ==========================================================
    # Unsafe HTTP methods
    # ==========================================================

    RISKY_METHODS=$(echo "$HTTP_OUTPUT" |
        sed -n 's/.*Potentially risky methods: \(.*\)/\1/p' |
        xargs)

    if [[ -n "$RISKY_METHODS" ]]; then

        echo "[!] Risky HTTP methods detected: $RISKY_METHODS"

        write_finding \
            "Risky HTTP Methods Enabled" \
            "HTTP port $PORT reports potentially risky methods: $RISKY_METHODS" \
            "Medium" \
            "Disable unnecessary HTTP methods, especially PUT and DELETE, unless they are explicitly required and properly restricted."

    fi

    # ==========================================================
    # Directory listing
    # ==========================================================

    DIRECTORY_LISTING=$(echo "$HTTP_OUTPUT" |
        grep -E "directory listing|folder with directory listing" |
        sed 's/^[[:space:]|]*//' |
        paste -sd ',' - |
        sed 's/,/, /g')

    if [[ -n "$DIRECTORY_LISTING" ]]; then

        echo "[!] Directory listing detected"

        write_finding \
            "Web Directory Listing Enabled" \
            "HTTP enumeration reported: $DIRECTORY_LISTING" \
            "Medium" \
            "Disable directory indexing where it is not required and restrict access to exposed directories."

    fi

    # ==========================================================
    # Information-disclosure files
    # ==========================================================

    INFO_FILES=$(echo "$HTTP_OUTPUT" |
        grep -E "Possible information file|Interesting, a readme|phpinfo" |
        sed 's/^[[:space:]|]*//' |
        paste -sd ',' - |
        sed 's/,/, /g')

    if [[ -n "$INFO_FILES" ]]; then

        echo "[!] Potential information-disclosure files detected"

        write_finding \
            "Potential Information Disclosure" \
            "HTTP enumeration reported: $INFO_FILES" \
            "Low" \
            "Remove unnecessary information-disclosure files such as phpinfo or exposed documentation from production web services."

    fi

    # ==========================================================
    # Incorrect web-file permissions
    # ==========================================================

    PERMISSION_ISSUE=$(echo "$HTTP_OUTPUT" |
        grep -i "Incorrect permissions" |
        sed 's/^[[:space:]|]*//' |
        paste -sd ',' - |
        sed 's/,/, /g')

    if [[ -n "$PERMISSION_ISSUE" ]]; then

        echo "[!] Incorrect web-file permissions detected"

        write_finding \
            "Incorrect Web File Permissions" \
            "HTTP enumeration reported: $PERMISSION_ISSUE" \
            "Medium" \
            "Correct the permissions of sensitive web configuration files and prevent them from being exposed or readable through the web server."
    fi
}

run_http_enum
