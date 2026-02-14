#!/bin/bash

# AIDOR Pro Advanced - Enterprise-Grade IDOR Vulnerability Scanner
# For Authorized Penetration Testing & Bug Bounty Programs Only
# Author: [N1xR00t~#]
# Enhanced with multi-threading, detailed logging, and advanced detection

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; NC='\033[0m'

# Configuration
OUTPUT_DIR="aidor_results_$(date +%Y%m%d_%H%M%S)"
THREADS=5
TIMEOUT=10
USER_AGENT="AIDOR-Scanner/2.0 (Security Research)"
VERBOSE=false

# Professional Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
  _____  _____   ____  _____  ______ _    _ _____ ______ ______ _____  
 |_   _||  __ \ / __ \|  __ \|  ____| |  | |      |___  /|  ____|  __ \ 
   | |  | |  | | |  | | |__) | |__  | |  | |__  /    / / | |__  | |__) |
   | |  | |  | | |  | |  _  /|  __| | |  | | / /    / /  |  __| |  _  / 
  _| |_ | |__| | |__| | | \ \| |    | |__| |/ /_   / /__ | |____| | \ \ 
 |_____||_____/ \____/|_|  \_\_|     \____//____| /_____||______|_|  \_\
EOF
    echo -e "${RED}           [ Advanced IDOR Detection Framework ]${NC}"
    echo -e "${RED}            Author: [N1xR00t~#]${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
}
# Dependency Check
check_deps() {
    local deps=("curl" "grep" "sed" "jq" "parallel")
    local missing=()
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}[i] Install with: sudo apt install ${missing[*]}${NC}"
        exit 1
    fi
}

# Initialize output directory
init_output() {
    mkdir -p "$OUTPUT_DIR"/{logs,reports,evidence}
    echo -e "${GREEN}[+] Output directory created: $OUTPUT_DIR${NC}"
}

# Advanced payload generation
generate_payloads() {
    local type="$1"
    local payloads=()
    
    case "$type" in
        "numeric")
            # Sequential, boundary, negative
            payloads=("0" "1" "2" "3" "10" "100" "999" "1000" "9999" "-1" "-100")
            ;;
        "uuid")
            # Common UUID patterns
            payloads=(
                "00000000-0000-0000-0000-000000000000"
                "11111111-1111-1111-1111-111111111111"
                "admin-admin-admin-admin-admin"
            )
            ;;
        "string")
            # Common string IDs
            payloads=("admin" "root" "user" "test" "demo" "guest" "null" "undefined" "me")
            ;;
        "encoded")
            # Base64 encoded
            payloads=("MQ==" "YWRtaW4=" "dXNlcg==" "MA==")
            ;;
        "special")
            # Special characters and injection attempts
            payloads=("../1" "..%2F1" "1'" '1"' "1;--" "1/**/")
            ;;
    esac
    
    echo "${payloads[@]}"
}

# Enhanced IDOR testing function
test_idor_advanced() {
    local base_url="$1"
    local endpoint="$2"
    local param="$3"
    local auth_header="$4"
    
    local log_file="$OUTPUT_DIR/logs/${endpoint//\//_}.log"
    local vuln_file="$OUTPUT_DIR/reports/vulnerabilities.txt"
    
    echo -e "${BLUE}[*] Testing:${NC} ${endpoint}?${param}=<FUZZ>" | tee -a "$log_file"
    
    # Combine all payload types
    local all_payloads=()
    for ptype in "numeric" "uuid" "string" "encoded" "special"; do
        all_payloads+=($(generate_payloads "$ptype"))
    done
    
    local baseline_size=0
    local baseline_code=0
    
    # Baseline request (legitimate ID)
    baseline_url="${base_url}${endpoint}?${param}=1"
    baseline_resp=$(curl -s -o /tmp/baseline_$$ -w "%{http_code}:%{size_download}:%{time_total}" \
                    -H "User-Agent: $USER_AGENT" \
                    ${auth_header:+-H "$auth_header"} \
                    --max-time "$TIMEOUT" \
                    "$baseline_url" 2>/dev/null)
    
    baseline_code=$(echo "$baseline_resp" | cut -d':' -f1)
    baseline_size=$(echo "$baseline_resp" | cut -d':' -f2)
    
    # Test each payload
    for payload in "${all_payloads[@]}"; do
        local test_url="${base_url}${endpoint}?${param}=${payload}"
        local response_file="/tmp/aidor_resp_$$_${RANDOM}"
        
        # Make request
        local result=$(curl -s -o "$response_file" \
                       -w "%{http_code}:%{size_download}:%{time_total}" \
                       -H "User-Agent: $USER_AGENT" \
                       ${auth_header:+-H "$auth_header"} \
                       --max-time "$TIMEOUT" \
                       "$test_url" 2>/dev/null)
        
        local code=$(echo "$result" | cut -d':' -f1)
        local size=$(echo "$result" | cut -d':' -f2)
        local time=$(echo "$result" | cut -d':' -f3)
        
        # Vulnerability analysis
        local vuln_level="SAFE"
        local findings=()
        
        if [[ "$code" == "200" ]]; then
            # Check for sensitive data patterns
            if grep -qiE "(\"email\"|\"password\"|\"token\"|\"api_key\"|\"secret\"|\"ssn\"|\"credit_card\")" "$response_file" 2>/dev/null; then
                findings+=("Sensitive data exposed")
                vuln_level="CRITICAL"
            fi
            
            # Check for user-specific data
            if grep -qiE "(\"user_id\"|\"username\"|\"first_name\"|\"last_name\"|\"address\"|\"phone\")" "$response_file" 2>/dev/null; then
                findings+=("User data accessible")
                [[ "$vuln_level" != "CRITICAL" ]] && vuln_level="HIGH"
            fi
            
            # Size anomaly detection (±20% from baseline)
            if [[ "$baseline_size" -gt 0 ]]; then
                local size_diff=$((size - baseline_size))
                local size_percent=$((size_diff * 100 / baseline_size))
                if [[ ${size_percent#-} -gt 20 ]]; then
                    findings+=("Size anomaly: ${size_percent}% difference")
                    [[ "$vuln_level" == "SAFE" ]] && vuln_level="MEDIUM"
                fi
            fi
            
            # Check response structure
            if command -v jq &>/dev/null && jq empty "$response_file" 2>/dev/null; then
                local json_keys=$(jq -r 'keys[]' "$response_file" 2>/dev/null | wc -l)
                if [[ "$json_keys" -gt 5 ]]; then
                    findings+=("Rich JSON response ($json_keys keys)")
                fi
            fi
        fi
        
        # Report findings
        if [[ "$vuln_level" != "SAFE" ]]; then
            echo -e "  ${RED}[🚨 $vuln_level VULNERABILITY]${NC}" | tee -a "$vuln_file"
            echo -e "    URL: $test_url" | tee -a "$vuln_file"
            echo -e "    Payload: $payload | Status: $code | Size: $size bytes | Time: ${time}s" | tee -a "$vuln_file"
            
            for finding in "${findings[@]}"; do
                echo -e "    └─ $finding" | tee -a "$vuln_file"
            done
            
            # Save evidence
            cp "$response_file" "$OUTPUT_DIR/evidence/${endpoint//\//_}_${payload//\//_}.html"
            echo "" | tee -a "$vuln_file"
        elif [[ "$VERBOSE" == true ]]; then
            echo -e "  ${GREEN}[✓]${NC} Payload: $payload | Status: $code | Size: $size"
        fi
        
        rm -f "$response_file"
    done
    
    rm -f /tmp/baseline_$$
}

# Smart endpoint discovery
discover_endpoints() {
    local base_url="$1"
    local discovered=()
    
    echo -e "${PURPLE}[*] Running endpoint discovery...${NC}"
    
    # Common API endpoints
    local common_endpoints=(
        # User Management
        "api/v1/users" "api/v2/users" "api/users" "users"
        "api/v1/user" "api/v2/user" "api/user" "user"
        "api/v1/profile" "api/profile" "profile" "account"
        
        # Data Access
        "api/v1/documents" "api/documents" "documents" "files"
        "api/v1/invoices" "api/invoices" "invoices" "billing"
        "api/v1/orders" "api/orders" "orders" "purchases"
        "api/v1/messages" "api/messages" "messages" "inbox"
        
        # Admin/Dashboard
        "api/v1/admin" "api/admin" "admin" "dashboard"
        "api/v1/settings" "api/settings" "settings"
        "api/v1/reports" "api/reports" "reports"
        
        # Other Common
        "api/v1/customers" "api/customers" "customers"
        "api/v1/accounts" "api/accounts" "accounts"
        "api/v1/downloads" "api/downloads" "download"
    )
    
    for endpoint in "${common_endpoints[@]}"; do
        local url="${base_url}${endpoint}"
        local status=$(curl -s -o /dev/null -w "%{http_code}" \
                       -H "User-Agent: $USER_AGENT" \
                       --max-time 5 \
                       "$url" 2>/dev/null)
        
        if [[ "$status" != "404" && "$status" != "000" ]]; then
            echo -e "${GREEN}[+] Found:${NC} /$endpoint (HTTP $status)"
            discovered+=("$endpoint")
        fi
    done
    
    echo "${discovered[@]}"
}

# Main scanning function
run_comprehensive_scan() {
    local target="$1"
    local auth_token="$2"
    
    # Normalize URL
    [[ "$target" != http* ]] && target="https://$target"
    [[ "$target" != */ ]] && target="$target/"
    
    echo -e "${GREEN}[+] Target:${NC} $target"
    [[ -n "$auth_token" ]] && echo -e "${GREEN}[+] Using Authorization:${NC} Bearer ***"
    
    # Discover endpoints
    local endpoints=($(discover_endpoints "$target"))
    
    if [[ ${#endpoints[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[!] No endpoints discovered. Using default list.${NC}"
        endpoints=("api/user" "api/users" "profile" "account" "documents" "orders")
    fi
    
    # Common parameter names for IDOR
    local params=("id" "user_id" "uid" "userId" "account_id" "doc_id" "order_id" "customer_id" "file_id" "message_id" "uuid")
    
    echo -e "\n${PURPLE}[*] Starting IDOR vulnerability assessment...${NC}\n"
    
    local total_tests=$((${#endpoints[@]} * ${#params[@]}))
    local current=0
    
    for endpoint in "${endpoints[@]}"; do
        for param in "${params[@]}"; do
            ((current++))
            echo -e "${CYAN}[Progress: $current/$total_tests]${NC}"
            test_idor_advanced "$target" "$endpoint" "$param" "${auth_token:+Authorization: Bearer $auth_token}"
        done
    done
}

# Generate final report
generate_report() {
    local report_file="$OUTPUT_DIR/FINAL_REPORT.txt"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}Generating comprehensive report...${NC}"
    
    cat > "$report_file" << EOF
╔═══════════════════════════════════════════════════════════════╗
║          AIDOR PRO - IDOR Vulnerability Assessment            ║
║                   FINAL SECURITY REPORT                       ║
╚═══════════════════════════════════════════════════════════════╝

Scan Date: $(date)
Target: $TARGET_URL
Scanner: AIDOR Pro Advanced v2.0

─────────────────────────────────────────────────────────────────

EXECUTIVE SUMMARY:
─────────────────────────────────────────────────────────────────

EOF
    
    if [[ -f "$OUTPUT_DIR/reports/vulnerabilities.txt" ]]; then
        local critical=$(grep -c "CRITICAL" "$OUTPUT_DIR/reports/vulnerabilities.txt" 2>/dev/null || echo 0)
        local high=$(grep -c "HIGH" "$OUTPUT_DIR/reports/vulnerabilities.txt" 2>/dev/null || echo 0)
        local medium=$(grep -c "MEDIUM" "$OUTPUT_DIR/reports/vulnerabilities.txt" 2>/dev/null || echo 0)
        
        cat >> "$report_file" << EOF
[CRITICAL] Vulnerabilities Found: $critical
[HIGH]     Vulnerabilities Found: $high
[MEDIUM]   Vulnerabilities Found: $medium

─────────────────────────────────────────────────────────────────

DETAILED FINDINGS:
─────────────────────────────────────────────────────────────────

EOF
        cat "$OUTPUT_DIR/reports/vulnerabilities.txt" >> "$report_file"
    else
        echo "No vulnerabilities detected." >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

─────────────────────────────────────────────────────────────────

RECOMMENDATIONS:
─────────────────────────────────────────────────────────────────

1. Implement proper authorization checks on all API endpoints
2. Use indirect object references (mapping tables)
3. Validate user permissions before data access
4. Implement rate limiting and monitoring
5. Use UUIDs instead of sequential IDs where possible
6. Apply principle of least privilege

─────────────────────────────────────────────────────────────────
Report generated by AIDOR Pro Advanced
For questions: Muhammad Rehan Afzal [N1xR00t~#]
─────────────────────────────────────────────────────────────────
EOF
    
    echo -e "${GREEN}[+] Report saved:${NC} $report_file"
    echo -e "${GREEN}[+] Evidence saved in:${NC} $OUTPUT_DIR/evidence/"
}

# Main Execution
main() {
    show_banner
    check_deps
    init_output
    
    # Get target
    read -p "🎯 Enter target URL or domain: " TARGET_URL
    if [[ -z "$TARGET_URL" ]]; then
        echo -e "${RED}[!] Target URL required${NC}"
        exit 1
    fi
    
    # Optional: Authentication
    read -p "🔑 Enter authorization token (optional, press Enter to skip): " AUTH_TOKEN
    
    # Optional: Verbose mode
    read -p "📊 Enable verbose mode? (y/N): " verbose_choice
    [[ "$verbose_choice" =~ ^[Yy]$ ]] && VERBOSE=true
    
    echo ""
    run_comprehensive_scan "$TARGET_URL" "$AUTH_TOKEN"
    generate_report
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[✓] SCAN COMPLETE${NC}"
    echo -e "${WHITE}Results saved in: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}[!] Always verify findings manually with Burp Suite/ZAP${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
}

# Run
main