#!/bin/bash

#############################################
# Master Bug Bounty Automation Script
# Combines: Wayback, Shodan, Nuclei, Arjun,
# Dalfox, Loxs, GF Patterns, and more
# Author: Enhanced by coffinxp methodology
# Version: 2.1 - Optimized workflow
#############################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║   MASTER BUG BOUNTY AUTOMATION FRAMEWORK v2.1           ║
║   Wayback + Shodan + Nuclei + XSS + IDOR + SQLi         ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Configuration
DOMAINS_FILE="$1"
OUTPUT_DIR="bug-hunt-$(date +%Y%m%d-%H%M%S)"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"  # Set via env variable
VT_API_KEY="${VT_API_KEY:-}"          # VirusTotal API key
THREADS=20
RATE_LIMIT=50
MAX_FILES_TO_CHECK=500  # Configurable limit for file accessibility checks

# Usage check
if [ -z "$DOMAINS_FILE" ] || [ ! -f "$DOMAINS_FILE" ]; then
    echo -e "${RED}[!] Usage: $0 <domains.txt>${NC}"
    echo -e "${YELLOW}[*] domains.txt should contain one domain per line${NC}"
    echo -e "${YELLOW}[*] Optional: Set SHODAN_API_KEY and VT_API_KEY as env variables${NC}"
    exit 1
fi

# Create directory structure
mkdir -p "$OUTPUT_DIR"/{wayback,shodan,nuclei,xss,idor,sqli,secrets,reports}

echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}"
echo -e "${CYAN}[*] Processing $(wc -l < $DOMAINS_FILE) domains...${NC}\n"

# Function to print status
print_status() {
    echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"
}

# Function to print success
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Function to print error
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to print info
print_info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

#############################################
# PHASE 1: SUBDOMAIN ENUMERATION
#############################################
print_status "PHASE 1: Subdomain Enumeration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

subdomain_enum() {
    local domain=$1
    print_info "Enumerating subdomains for $domain..."
    
    # Multiple sources
    subfinder -d "$domain" -silent -all >> "$OUTPUT_DIR/subdomains_raw.txt" 2>/dev/null
    assetfinder --subs-only "$domain" >> "$OUTPUT_DIR/subdomains_raw.txt" 2>/dev/null
}

while IFS= read -r domain; do
    # Strip protocol if present
    clean_domain=$(echo "$domain" | sed 's|https\?://||' | cut -d'/' -f1)
    subdomain_enum "$clean_domain" &
done < "$DOMAINS_FILE"
wait

# Add input domains to subdomain list
cat "$DOMAINS_FILE" | sed 's|https\?://||' | cut -d'/' -f1 >> "$OUTPUT_DIR/subdomains_raw.txt"

# Deduplicate subdomains
sort -u "$OUTPUT_DIR/subdomains_raw.txt" > "$OUTPUT_DIR/all_subdomains.txt"
rm "$OUTPUT_DIR/subdomains_raw.txt" 2>/dev/null

print_success "Total subdomains (including input): $(wc -l < $OUTPUT_DIR/all_subdomains.txt)"

#############################################
# PHASE 2: WAYBACK MACHINE RECONNAISSANCE
#############################################
print_status "\nPHASE 2: Wayback Machine URL Extraction"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

wayback_extract() {
    local domain=$1
    local output_file="$OUTPUT_DIR/wayback/${domain}_wayback.txt"
    
    print_info "Extracting Wayback URLs for $domain..."
    
    # Method 1: Direct Wayback CDX API
    curl -sG "https://web.archive.org/cdx/search/cdx" \
        --data-urlencode "url=*.${domain}/*" \
        --data-urlencode "collapse=urlkey" \
        --data-urlencode "output=text" \
        --data-urlencode "fl=original" > "$output_file" 2>/dev/null
    
    # Method 2: Also use gau for additional coverage
    gau "$domain" --threads $THREADS >> "$output_file" 2>/dev/null
    
    # Deduplicate
    sort -u "$output_file" -o "$output_file"
    
    local count=$(wc -l < "$output_file")
    print_success "Found $count URLs for $domain"
}

# Extract wayback URLs for ALL discovered subdomains (including dead ones)
print_info "Running Wayback extraction on all discovered subdomains..."
while IFS= read -r domain; do
    wayback_extract "$domain" &
    
    # Limit concurrent jobs
    if [[ $(jobs -r -p | wc -l) -ge $THREADS ]]; then
        wait -n
    fi
done < "$OUTPUT_DIR/all_subdomains.txt"
wait

# Combine all wayback URLs
cat "$OUTPUT_DIR"/wayback/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/wayback/all_wayback_urls.txt"
print_success "Total unique Wayback URLs: $(wc -l < $OUTPUT_DIR/wayback/all_wayback_urls.txt)"

#############################################
# PHASE 3: ALIVE SUBDOMAIN CHECK
#############################################
print_status "\nPHASE 3: Checking Alive Subdomains"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Filtering alive subdomains with httpx..."
cat "$OUTPUT_DIR/all_subdomains.txt" | httpx -silent -threads $THREADS -mc 200,301,302,403 -o "$OUTPUT_DIR/alive_subdomains.txt"

print_success "Alive subdomains: $(wc -l < $OUTPUT_DIR/alive_subdomains.txt) / $(wc -l < $OUTPUT_DIR/all_subdomains.txt)"

#############################################
# PHASE 4: SENSITIVE FILE DISCOVERY
#############################################
print_status "\nPHASE 4: Sensitive File Discovery"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Filtering sensitive file extensions..."

# Filter sensitive files
grep -iE '\.(pdf|xls|xlsx|doc|docx|csv|sql|db|zip|tar|gz|rar|7z|bak|backup|old|json|xml|config|conf|env|log|txt)$' \
    "$OUTPUT_DIR/wayback/all_wayback_urls.txt" > "$OUTPUT_DIR/secrets/sensitive_files.txt" 2>/dev/null

# Categorize by type
grep -iE '\.(pdf|doc|docx|xls|xlsx)$' "$OUTPUT_DIR/secrets/sensitive_files.txt" > "$OUTPUT_DIR/secrets/documents.txt" 2>/dev/null
grep -iE '\.(sql|db|sqlite|mdb)$' "$OUTPUT_DIR/secrets/sensitive_files.txt" > "$OUTPUT_DIR/secrets/databases.txt" 2>/dev/null
grep -iE '\.(zip|tar|gz|rar|7z)$' "$OUTPUT_DIR/secrets/sensitive_files.txt" > "$OUTPUT_DIR/secrets/archives.txt" 2>/dev/null
grep -iE '\.(bak|backup|old|env|config|conf)$' "$OUTPUT_DIR/secrets/sensitive_files.txt" > "$OUTPUT_DIR/secrets/config_files.txt" 2>/dev/null

print_success "Documents: $(wc -l < $OUTPUT_DIR/secrets/documents.txt)"
print_success "Databases: $(wc -l < $OUTPUT_DIR/secrets/databases.txt)"
print_success "Archives: $(wc -l < $OUTPUT_DIR/secrets/archives.txt)"
print_success "Configs: $(wc -l < $OUTPUT_DIR/secrets/config_files.txt)"

# Check if files are accessible (404 technique)
print_info "Checking file accessibility (max $MAX_FILES_TO_CHECK files)..."

check_file_status() {
    local url=$1
    local status=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 10 "$url")
    
    if [ "$status" == "404" ]; then
        # Check Wayback Machine for archived version
        local wayback_url="https://web.archive.org/web/*/${url}"
        echo "$url|404|CHECK_ARCHIVE:$wayback_url" >> "$OUTPUT_DIR/secrets/404_check_archive.txt"
    elif [ "$status" == "200" ]; then
        echo "$url|200|ACCESSIBLE" >> "$OUTPUT_DIR/secrets/accessible_files.txt"
    else
        echo "$url|$status|OTHER" >> "$OUTPUT_DIR/secrets/other_status.txt"
    fi
}

# Check files with configurable limit
head -"$MAX_FILES_TO_CHECK" "$OUTPUT_DIR/secrets/sensitive_files.txt" | while read -r url; do
    check_file_status "$url" &
    # Limit concurrent connections
    if [[ $(jobs -r -p | wc -l) -ge $THREADS ]]; then
        wait -n
    fi
done
wait

print_success "File status check complete"
print_info "404 files to check in Wayback: $(wc -l < $OUTPUT_DIR/secrets/404_check_archive.txt 2>/dev/null || echo 0)"
print_info "Accessible files: $(wc -l < $OUTPUT_DIR/secrets/accessible_files.txt 2>/dev/null || echo 0)"

#############################################
# PHASE 5: SHODAN RECONNAISSANCE (if API key)
#############################################
if [ -n "$SHODAN_API_KEY" ]; then
    print_status "\nPHASE 5: Shodan Reconnaissance"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    print_info "Searching Shodan for each domain..."
    
    while IFS= read -r domain; do
        print_info "Shodan search: $domain"
        shodan search "hostname:$domain" > "$OUTPUT_DIR/shodan/${domain}_shodan.txt" 2>/dev/null || true
    done < "$DOMAINS_FILE"
    
    print_success "Shodan results saved in $OUTPUT_DIR/shodan/"
else
    print_info "\n[!] PHASE 5: Shodan skipped (no API key)"
    print_info "    Set SHODAN_API_KEY environment variable to enable"
fi

#############################################
# PHASE 6: URL CRAWLING & PARAMETER DISCOVERY
#############################################
print_status "\nPHASE 6: Deep URL Crawling"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Crawling with Katana..."
cat "$OUTPUT_DIR/alive_subdomains.txt" | \
    katana -d 3 -jc -silent -c $THREADS \
    -o "$OUTPUT_DIR/crawled_urls.txt"

# Combine all URLs
cat "$OUTPUT_DIR/wayback/all_wayback_urls.txt" \
    "$OUTPUT_DIR/crawled_urls.txt" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/all_urls.txt"

print_success "Total URLs collected: $(wc -l < $OUTPUT_DIR/all_urls.txt)"

#############################################
# PHASE 7: XSS HUNTING PIPELINE
#############################################
print_status "\nPHASE 7: XSS Vulnerability Hunting"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Filtering XSS candidates with GF..."
cat "$OUTPUT_DIR/all_urls.txt" | gf xss > "$OUTPUT_DIR/xss/xss_candidates.txt" 2>/dev/null || true

print_info "Deduplicating with URO..."
cat "$OUTPUT_DIR/xss/xss_candidates.txt" | uro > "$OUTPUT_DIR/xss/xss_unique.txt"

print_success "Unique XSS candidates: $(wc -l < $OUTPUT_DIR/xss/xss_unique.txt)"

print_info "Finding reflected parameters with GXSS..."
cat "$OUTPUT_DIR/xss/xss_unique.txt" | \
    Gxss -c $THREADS -p test > "$OUTPUT_DIR/xss/reflected.txt" 2>/dev/null || true

print_success "Reflected parameters: $(wc -l < $OUTPUT_DIR/xss/reflected.txt)"

if [ -s "$OUTPUT_DIR/xss/reflected.txt" ]; then
    print_info "Scanning with Dalfox..."
    cat "$OUTPUT_DIR/xss/reflected.txt" | \
        dalfox pipe \
        --skip-bav \
        --only-poc r \
        --silence \
        --format json \
        -o "$OUTPUT_DIR/xss/dalfox_results.json" 2>/dev/null || true
    
    DALFOX_FINDINGS=$(cat "$OUTPUT_DIR/xss/dalfox_results.json" 2>/dev/null | grep -c "PoC" || echo "0")
    print_success "Dalfox XSS findings: $DALFOX_FINDINGS"
    
    # Save for Loxs testing
    head -50 "$OUTPUT_DIR/xss/reflected.txt" > "$OUTPUT_DIR/xss/loxs_targets.txt"
    print_info "Prepared $(wc -l < $OUTPUT_DIR/xss/loxs_targets.txt) URLs for manual Loxs testing"
fi

#############################################
# PHASE 8: IDOR HUNTING PIPELINE
#############################################
print_status "\nPHASE 8: IDOR Vulnerability Hunting"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Filtering IDOR candidates..."
cat "$OUTPUT_DIR/all_urls.txt" | gf idor > "$OUTPUT_DIR/idor/idor_candidates.txt" 2>/dev/null || true

# Additional manual filtering
cat "$OUTPUT_DIR/all_urls.txt" | \
    grep -iE "(id|user|account|profile|doc|order|invoice|number|email|uid|pid)=" \
    >> "$OUTPUT_DIR/idor/idor_candidates.txt"

sort -u "$OUTPUT_DIR/idor/idor_candidates.txt" -o "$OUTPUT_DIR/idor/idor_candidates.txt"

print_info "Deduplicating IDOR URLs..."
cat "$OUTPUT_DIR/idor/idor_candidates.txt" | uro > "$OUTPUT_DIR/idor/idor_unique.txt"

print_success "Unique IDOR candidates: $(wc -l < $OUTPUT_DIR/idor/idor_unique.txt)"

print_info "Discovering hidden parameters with Arjun..."
arjun -i "$OUTPUT_DIR/idor/idor_unique.txt" \
    -o "$OUTPUT_DIR/idor/arjun_params.json" \
    -t $THREADS \
    --passive 2>/dev/null || true

print_info "Extracting numeric IDs..."
cat "$OUTPUT_DIR/idor/idor_unique.txt" | \
    grep -oP '\d{4,}' | sort -u > "$OUTPUT_DIR/idor/numeric_ids.txt"

print_success "Unique numeric IDs: $(wc -l < $OUTPUT_DIR/idor/numeric_ids.txt)"

# Extract API endpoints for Burp testing
cat "$OUTPUT_DIR/idor/idor_unique.txt" | \
    grep -iE "api|/v[0-9]|graphql" > "$OUTPUT_DIR/idor/api_endpoints.txt" 2>/dev/null || true

print_success "API endpoints for Autorize: $(wc -l < $OUTPUT_DIR/idor/api_endpoints.txt)"

#############################################
# PHASE 9: SQL INJECTION DETECTION
#############################################
print_status "\nPHASE 9: SQL Injection Detection"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Filtering SQLi candidates..."
cat "$OUTPUT_DIR/all_urls.txt" | gf sqli > "$OUTPUT_DIR/sqli/sqli_candidates.txt" 2>/dev/null || true

cat "$OUTPUT_DIR/sqli/sqli_candidates.txt" | uro > "$OUTPUT_DIR/sqli/sqli_unique.txt"

print_success "Unique SQLi candidates: $(wc -l < $OUTPUT_DIR/sqli/sqli_unique.txt)"

# Save for Loxs manual testing
head -50 "$OUTPUT_DIR/sqli/sqli_unique.txt" > "$OUTPUT_DIR/sqli/loxs_targets.txt"
print_info "Prepared $(wc -l < $OUTPUT_DIR/sqli/loxs_targets.txt) URLs for manual Loxs testing"

#############################################
# PHASE 10: NUCLEI VULNERABILITY SCANNING
#############################################
print_status "\nPHASE 10: Nuclei Automated Scanning"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Running Nuclei on alive subdomains..."

# Update templates
nuclei -update-templates -silent 2>/dev/null || true

# Scan for exposures
cat "$OUTPUT_DIR/alive_subdomains.txt" | \
    nuclei -t ~/nuclei-templates/http/exposures/ \
    -c $THREADS \
    -rl $RATE_LIMIT \
    -o "$OUTPUT_DIR/nuclei/exposures.txt" \
    -silent 2>/dev/null || true

# Scan for CVEs (if available)
cat "$OUTPUT_DIR/alive_subdomains.txt" | \
    nuclei -t ~/nuclei-templates/http/cves/ \
    -c $THREADS \
    -rl $RATE_LIMIT \
    -o "$OUTPUT_DIR/nuclei/cves.txt" \
    -silent 2>/dev/null || true

# Scan for misconfigurations
cat "$OUTPUT_DIR/alive_subdomains.txt" | \
    nuclei -t ~/nuclei-templates/http/misconfiguration/ \
    -c $THREADS \
    -rl $RATE_LIMIT \
    -o "$OUTPUT_DIR/nuclei/misconfigs.txt" \
    -silent 2>/dev/null || true

print_success "Nuclei exposures: $(wc -l < $OUTPUT_DIR/nuclei/exposures.txt 2>/dev/null || echo 0)"
print_success "Nuclei CVEs: $(wc -l < $OUTPUT_DIR/nuclei/cves.txt 2>/dev/null || echo 0)"
print_success "Nuclei misconfigs: $(wc -l < $OUTPUT_DIR/nuclei/misconfigs.txt 2>/dev/null || echo 0)"

#############################################
# PHASE 11: SECRET SCANNING
#############################################
print_status "\nPHASE 11: Secret & Token Discovery"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

print_info "Extracting JavaScript files..."
cat "$OUTPUT_DIR/all_urls.txt" | \
    grep -iE "\.js($|\?)" | sort -u > "$OUTPUT_DIR/secrets/js_files.txt"

print_success "JavaScript files: $(wc -l < $OUTPUT_DIR/secrets/js_files.txt)"

print_info "Scanning JS files for secrets with Nuclei..."
cat "$OUTPUT_DIR/secrets/js_files.txt" | \
    nuclei -t ~/nuclei-templates/http/exposures/ \
    -t ~/nuclei-templates/file/keys/ \
    -c $THREADS \
    -o "$OUTPUT_DIR/secrets/js_secrets.txt" \
    -silent 2>/dev/null || true

print_success "Secrets found in JS: $(wc -l < $OUTPUT_DIR/secrets/js_secrets.txt 2>/dev/null || echo 0)"

#############################################
# PHASE 12: VIRUSTOTAL INTEGRATION (if API key)
#############################################
if [ -n "$VT_API_KEY" ]; then
    print_status "\nPHASE 12: VirusTotal Intelligence"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    vt_search() {
        local domain=$1
        print_info "VirusTotal search: $domain"
        
        curl -s --request GET \
            --url "https://www.virustotal.com/api/v3/domains/${domain}/urls" \
            --header "x-apikey: $VT_API_KEY" \
            > "$OUTPUT_DIR/virustotal/${domain}_vt.json" 2>/dev/null || true
    }
    
    mkdir -p "$OUTPUT_DIR/virustotal"
    
    while IFS= read -r domain; do
        clean_domain=$(echo "$domain" | sed 's|https\?://||' | cut -d'/' -f1)
        vt_search "$clean_domain" &
        sleep 1  # Rate limiting
    done < "$DOMAINS_FILE"
    wait
    
    print_success "VirusTotal results saved"
else
    print_info "\n[!] PHASE 12: VirusTotal skipped (no API key)"
    print_info "    Set VT_API_KEY environment variable to enable"
fi

#############################################
# PHASE 13: GENERATE FINAL REPORT
#############################################
print_status "\nPHASE 13: Generating Summary Report"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

REPORT_FILE="$OUTPUT_DIR/reports/SUMMARY_REPORT.txt"

cat > "$REPORT_FILE" << EOF
═══════════════════════════════════════════════════════════
    BUG BOUNTY AUTOMATION REPORT
═══════════════════════════════════════════════════════════
Generated: $(date)
Input Domains: $(wc -l < $DOMAINS_FILE)
Output Directory: $OUTPUT_DIR

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RECONNAISSANCE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total URLs Collected:     $(wc -l < $OUTPUT_DIR/all_urls.txt)
All Subdomains Found:     $(wc -l < $OUTPUT_DIR/all_subdomains.txt)
Alive Subdomains:         $(wc -l < $OUTPUT_DIR/alive_subdomains.txt)
Wayback URLs:            $(wc -l < $OUTPUT_DIR/wayback/all_wayback_urls.txt)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SENSITIVE FILES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Documents (PDF/DOC/XLS): $(wc -l < $OUTPUT_DIR/secrets/documents.txt 2>/dev/null || echo 0)
Database Files:           $(wc -l < $OUTPUT_DIR/secrets/databases.txt 2>/dev/null || echo 0)
Archive Files:            $(wc -l < $OUTPUT_DIR/secrets/archives.txt 2>/dev/null || echo 0)
Config Files:             $(wc -l < $OUTPUT_DIR/secrets/config_files.txt 2>/dev/null || echo 0)
Accessible Files (200):   $(wc -l < $OUTPUT_DIR/secrets/accessible_files.txt 2>/dev/null || echo 0)
404 Files (Check Archive): $(wc -l < $OUTPUT_DIR/secrets/404_check_archive.txt 2>/dev/null || echo 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
XSS HUNTING RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
XSS Candidates:          $(wc -l < $OUTPUT_DIR/xss/xss_candidates.txt 2>/dev/null || echo 0)
Unique XSS URLs:         $(wc -l < $OUTPUT_DIR/xss/xss_unique.txt 2>/dev/null || echo 0)
Reflected Parameters:    $(wc -l < $OUTPUT_DIR/xss/reflected.txt 2>/dev/null || echo 0)
Dalfox Findings:         $(cat $OUTPUT_DIR/xss/dalfox_results.json 2>/dev/null | grep -c "PoC" || echo 0)
Ready for Loxs:          $(wc -l < $OUTPUT_DIR/xss/loxs_targets.txt 2>/dev/null || echo 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IDOR HUNTING RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IDOR Candidates:         $(wc -l < $OUTPUT_DIR/idor/idor_candidates.txt 2>/dev/null || echo 0)
Unique IDOR URLs:        $(wc -l < $OUTPUT_DIR/idor/idor_unique.txt 2>/dev/null || echo 0)
Numeric IDs Extracted:   $(wc -l < $OUTPUT_DIR/idor/numeric_ids.txt 2>/dev/null || echo 0)
API Endpoints:           $(wc -l < $OUTPUT_DIR/idor/api_endpoints.txt 2>/dev/null || echo 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SQL INJECTION RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SQLi Candidates:         $(wc -l < $OUTPUT_DIR/sqli/sqli_candidates.txt 2>/dev/null || echo 0)
Unique SQLi URLs:        $(wc -l < $OUTPUT_DIR/sqli/sqli_unique.txt 2>/dev/null || echo 0)
Ready for Loxs:          $(wc -l < $OUTPUT_DIR/sqli/loxs_targets.txt 2>/dev/null || echo 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NUCLEI SCAN RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Exposures Found:         $(wc -l < $OUTPUT_DIR/nuclei/exposures.txt 2>/dev/null || echo 0)
CVEs Found:              $(wc -l < $OUTPUT_DIR/nuclei/cves.txt 2>/dev/null || echo 0)
Misconfigurations:       $(wc -l < $OUTPUT_DIR/nuclei/misconfigs.txt 2>/dev/null || echo 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECRETS & TOKENS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
JavaScript Files:        $(wc -l < $OUTPUT_DIR/secrets/js_files.txt 2>/dev/null || echo 0)
Secrets in JS:           $(wc -l < $OUTPUT_DIR/secrets/js_secrets.txt 2>/dev/null || echo 0)

═══════════════════════════════════════════════════════════
NEXT STEPS - MANUAL TESTING REQUIRED
═══════════════════════════════════════════════════════════

1. XSS Testing with Loxs:
   cd ~/Cyber/newtoys/loxs && source venv/bin/activate
   python3 loxs.py
   → Select XSS, use file: $OUTPUT_DIR/xss/loxs_targets.txt

2. IDOR Testing with Burp + Autorize:
   → Import: $OUTPUT_DIR/idor/api_endpoints.txt
   → Configure Autorize with 2 user sessions
   → Test ID manipulation from: $OUTPUT_DIR/idor/numeric_ids.txt

3. SQLi Testing with Loxs:
   cd ~/Cyber/newtoys/loxs && source venv/bin/activate
   python3 loxs.py
   → Select SQLi, use file: $OUTPUT_DIR/sqli/loxs_targets.txt

4. Check 404 Files in Wayback Machine:
   → Review: $OUTPUT_DIR/secrets/404_check_archive.txt
   → Paste URLs into https://web.archive.org

5. Download Accessible Sensitive Files:
   → Review: $OUTPUT_DIR/secrets/accessible_files.txt
   → Download and analyze for information disclosure

6. Review Nuclei Findings:
   → High Priority: $OUTPUT_DIR/nuclei/cves.txt
   → Medium Priority: $OUTPUT_DIR/nuclei/exposures.txt
   → Check: $OUTPUT_DIR/nuclei/misconfigs.txt

7. Analyze Arjun Results:
   → Hidden parameters: $OUTPUT_DIR/idor/arjun_params.json
   → Test these parameters manually for IDORs

═══════════════════════════════════════════════════════════
PRIORITY TARGETS (Review These First)
═══════════════════════════════════════════════════════════
EOF

# Add high priority findings to report
if [ -s "$OUTPUT_DIR/secrets/accessible_files.txt" ]; then
    echo "" >> "$REPORT_FILE"
    echo "🔥 ACCESSIBLE SENSITIVE FILES:" >> "$REPORT_FILE"
    head -10 "$OUTPUT_DIR/secrets/accessible_files.txt" >> "$REPORT_FILE"
fi

if [ -s "$OUTPUT_DIR/nuclei/cves.txt" ]; then
    echo "" >> "$REPORT_FILE"
    echo "🔥 CVEs DETECTED:" >> "$REPORT_FILE"
    head -10 "$OUTPUT_DIR/nuclei/cves.txt" >> "$REPORT_FILE"
fi

if [ -s "$OUTPUT_DIR/secrets/js_secrets.txt" ]; then
    echo "" >> "$REPORT_FILE"
    echo "🔥 SECRETS IN JAVASCRIPT:" >> "$REPORT_FILE"
    head -10 "$OUTPUT_DIR/secrets/js_secrets.txt" >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"
echo "═══════════════════════════════════════════════════════════" >> "$REPORT_FILE"
echo "Report saved: $REPORT_FILE" >> "$REPORT_FILE"
echo "═══════════════════════════════════════════════════════════" >> "$REPORT_FILE"

# Display the report
cat "$REPORT_FILE"

# Create quick access scripts
cat > "$OUTPUT_DIR/quick_commands.sh" << 'QUICKEOF'
#!/bin/bash
# Quick access commands for manual testing

echo "Quick Commands for Manual Testing"
echo "=================================="
echo ""
echo "1. Test XSS with Loxs:"
echo "   cd ~/Cyber/newtoys/loxs && source venv/bin/activate && python3 loxs.py"
echo ""
echo "2. Test SQLi with Loxs:"
echo "   cd ~/Cyber/newtoys/loxs && source venv/bin/activate && python3 loxs.py"
echo ""
echo "3. Check 404 files in Wayback:"
echo "   cat secrets/404_check_archive.txt"
echo ""
echo "4. View Nuclei CVEs:"
echo "   cat nuclei/cves.txt"
echo ""
echo "5. Download accessible files:"
echo "   wget -i secrets/accessible_files.txt -P downloaded_files/"
echo ""
echo "6. View all findings:"
echo "   cat reports/SUMMARY_REPORT.txt"
QUICKEOF

chmod +x "$OUTPUT_DIR/quick_commands.sh"

print_success "\nScan complete! Check $OUTPUT_DIR/reports/SUMMARY_REPORT.txt"
print_info "Quick commands: $OUTPUT_DIR/quick_commands.sh"

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              AUTOMATION COMPLETE!                        ║${NC}"
echo -e "${GREEN}║   Review the summary report and start manual testing    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
