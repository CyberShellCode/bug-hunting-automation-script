# 🎯 Master Bug Bounty Automation Framework

A comprehensive, automated bug bounty reconnaissance and vulnerability hunting framework that combines the methodologies of top security researchers like **coffinxp**, **NahamSec**, and **TomNomNom**.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Understanding Output](#understanding-output)
- [Manual Testing Phase](#manual-testing-phase)
- [Advanced Configuration](#advanced-configuration)
- [Methodology](#methodology)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)

---

## 🔍 Overview

This framework automates **12 phases** of bug bounty hunting, from reconnaissance to vulnerability detection. It chains together 20+ tools to find:

- 🔓 **XSS** (Cross-Site Scripting)
- 🔐 **IDOR** (Insecure Direct Object References)
- 💉 **SQLi** (SQL Injection)
- 🗝️ **Exposed Secrets & API Keys**
- 📄 **Sensitive Files** (404 Wayback Technique)
- 🛡️ **CVEs & Misconfigurations**

**Runtime:** 20-60 minutes per target (depending on scope)  
**Output:** Organized reports with prioritized findings

---

## ✨ Features

### Automated Reconnaissance
- ✅ Wayback Machine URL extraction (coffinxp's technique)
- ✅ Subdomain enumeration (multiple sources)
- ✅ Deep web crawling (Katana + GAU)
- ✅ Parameter discovery (Arjun)
- ✅ JavaScript analysis for secrets

### Vulnerability Detection
- ✅ **XSS Pipeline:** GF → URO → GXSS → Dalfox
- ✅ **IDOR Pipeline:** GF → Arjun → ID extraction → Burp prep
- ✅ **SQLi Detection:** GF patterns + Loxs prep
- ✅ **Nuclei Scanning:** CVEs, exposures, misconfigs
- ✅ **Secret Scanning:** API keys, tokens, credentials

### Smart Filtering
- ✅ Uses GF patterns (coffinxp's collection)
- ✅ URO deduplication
- ✅ Reflected parameter detection
- ✅ Automatic prioritization

### 404 Wayback Technique
- ✅ Finds deleted/archived files
- ✅ Checks accessibility (200 vs 404)
- ✅ Generates Wayback URLs for manual checking
- ✅ Categorizes by file type (PDFs, DBs, configs)

---

## 🛠️ Installation

### Step 1: Clone/Download Scripts

```bash
# Create working directory
mkdir -p ~/bug-bounty-tools
cd ~/bug-bounty-tools

# Save the three main scripts:
# 1. master-bug-hunter.sh
# 2. preflight-check.sh  
# 3. install-all-tools-fixed.sh
```

### Step 2: Make Scripts Executable

```bash
chmod +x ~/bug-bounty-tools/master-bug-hunter.sh
chmod +x ~/bug-bounty-tools/preflight-check.sh
chmod +x ~/bug-bounty-tools/install-all-tools-fixed.sh
```

### Step 3: Install All Tools

```bash
# Run the installer
~/bug-bounty-tools/install-all-tools-fixed.sh

# This installs:
# - Core: curl, wget, git, go, python3
# - Go tools: gau, subfinder, httpx, katana, nuclei, etc.
# - Python tools: arjun, uro
# - Patterns: GF patterns, Nuclei templates
```

### Step 4: Run Preflight Check

```bash
~/bug-bounty-tools/preflight-check.sh

# Should show: ✓ ALL CRITICAL TOOLS ARE READY!
```

---

## 📦 Prerequisites

### Required Tools
| Tool | Purpose | Install Command |
|------|---------|-----------------|
| **gau** | URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **subfinder** | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | Alive checking | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **katana** | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **nuclei** | Vuln scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **arjun** | Parameter discovery | `pip3 install arjun` |
| **gf** | Pattern filtering | `go install github.com/tomnomnom/gf@latest` |
| **uro** | URL deduplication | `pip3 install uro` |
| **Gxss** | Reflected params | `go install github.com/KathanP19/Gxss@latest` |
| **dalfox** | XSS scanner | `go install github.com/hahwul/dalfox/v2@latest` |

### Optional (for manual testing)
- **Loxs** - XSS/SQLi/IDOR testing tool
- **Burp Suite + Autorize** - IDOR automation
- **Shodan API** - Infrastructure scanning
- **VirusTotal API** - URL intelligence

### System Requirements
- **OS:** Linux (Kali/Ubuntu/Debian)
- **RAM:** 2GB minimum (4GB+ recommended)
- **Disk:** 5GB+ free space
- **Network:** Stable internet connection

---

## 🚀 Quick Start

### 1. Create Targets File

```bash
# Create a file with target domains (one per line)
nano targets.txt
```

**Example targets.txt:**
```
example.com
target.com
bugbounty.com
```

### 2. Set API Keys (Optional)

```bash
# Get keys from:
# - Shodan: https://account.shodan.io/
# - VirusTotal: https://www.virustotal.com/gui/my-apikey

export SHODAN_API_KEY="your_shodan_key"
export VT_API_KEY="your_virustotal_key"

# Make permanent
echo 'export SHODAN_API_KEY="your_key"' >> ~/.bashrc
echo 'export VT_API_KEY="your_key"' >> ~/.bashrc
source ~/.bashrc
```

### 3. Run the Scanner

```bash
# Basic usage
~/bug-bounty-tools/master-bug-hunter.sh targets.txt

# Or use tmux for long scans
tmux new -s hunt
~/bug-bounty-tools/master-bug-hunter.sh targets.txt
# Ctrl+B then D to detach
```

### 4. Monitor Progress

The script displays real-time progress through 12 phases:
```
[10:30:15] PHASE 1: Wayback Machine URL Extraction
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[*] Extracting Wayback URLs for example.com...
[✓] Found 15,234 URLs for example.com
```

### 5. Review Results

```bash
# View summary report
cat bug-hunt-*/reports/SUMMARY_REPORT.txt

# Check high-priority findings
cat bug-hunt-*/secrets/accessible_files.txt
cat bug-hunt-*/nuclei/cves.txt
```

---

## 📖 Usage

### Basic Usage

```bash
./master-bug-hunter.sh <targets.txt>
```

### Output Structure

The script creates a timestamped directory:

```
bug-hunt-20250930-143022/
├── wayback/                 # Historical URLs
│   ├── all_wayback_urls.txt
│   └── domain_wayback.txt
├── secrets/                 # Sensitive files
│   ├── documents.txt        # PDFs, DOCs, XLS
│   ├── databases.txt        # SQL, DB files
│   ├── archives.txt         # ZIP, TAR, RAR
│   ├── config_files.txt     # ENV, CONFIG
│   ├── accessible_files.txt # 200 OK files
│   ├── 404_check_archive.txt # Check in Wayback
│   └── js_files.txt         # JavaScript files
├── xss/                     # XSS hunting
│   ├── xss_candidates.txt
│   ├── xss_unique.txt
│   ├── reflected.txt        # Reflected params
│   ├── dalfox_results.json
│   └── loxs_targets.txt     # Ready for Loxs
├── idor/                    # IDOR hunting
│   ├── idor_candidates.txt
│   ├── idor_unique.txt
│   ├── numeric_ids.txt      # IDs to test
│   ├── arjun_params.json    # Hidden params
│   └── api_endpoints.txt    # For Burp
├── sqli/                    # SQL injection
│   ├── sqli_candidates.txt
│   ├── sqli_unique.txt
│   └── loxs_targets.txt
├── nuclei/                  # Automated scans
│   ├── exposures.txt
│   ├── cves.txt
│   └── misconfigs.txt
├── shodan/                  # Shodan results
├── virustotal/              # VT results
└── reports/
    └── SUMMARY_REPORT.txt   # Main report
```

---

## 📊 Understanding Output

### Phase-by-Phase Breakdown

#### Phase 1: Wayback Machine
**What it does:** Extracts all historical URLs using Wayback CDX API + GAU  
**Output:** `wayback/all_wayback_urls.txt`  
**Why:** Finds deleted endpoints, old APIs, forgotten files

#### Phase 2: Sensitive File Discovery
**What it does:** Filters for PDFs, databases, configs, archives  
**Output:** Categorized files + accessibility check  
**Golden Technique:** Creates `404_check_archive.txt` - files to check in Wayback

#### Phase 3: Subdomain Enumeration
**What it does:** Multiple sources (subfinder, assetfinder, wayback)  
**Output:** `subdomains.txt` + `alive_subdomains.txt`  
**Why:** Expands attack surface

#### Phase 4: Shodan (Optional)
**What it does:** Searches for exposed services, CVEs  
**Output:** `shodan/domain_shodan.txt`  
**Requires:** SHODAN_API_KEY

#### Phase 5: Deep Crawling
**What it does:** Katana crawl (3 levels) + combines all URLs  
**Output:** `all_urls.txt`  
**Why:** Discovers hidden endpoints

#### Phase 6: XSS Pipeline
**What it does:** GF filter → URO dedupe → GXSS reflect → Dalfox scan  
**Output:** `xss/reflected.txt`, `xss/dalfox_results.json`  
**Why:** Finds XSS candidates with reflected input

#### Phase 7: IDOR Pipeline
**What it does:** GF filter → Arjun params → Extract IDs  
**Output:** `idor/numeric_ids.txt`, `idor/api_endpoints.txt`  
**Why:** Prepares for authorization testing

#### Phase 8: SQLi Detection
**What it does:** GF filter → URO dedupe  
**Output:** `sqli/sqli_unique.txt`  
**Why:** Finds SQL injection candidates

#### Phase 9: Nuclei Scanning
**What it does:** Automated vuln scanning (exposures, CVEs, misconfigs)  
**Output:** `nuclei/exposures.txt`, `nuclei/cves.txt`  
**Why:** Quick wins, known vulnerabilities

#### Phase 10: Secret Scanning
**What it does:** Extracts JS files, scans for API keys/tokens  
**Output:** `secrets/js_secrets.txt`  
**Why:** API keys, credentials, tokens

#### Phase 11: VirusTotal (Optional)
**What it does:** Searches VT for associated URLs  
**Output:** `virustotal/domain_vt.json`  
**Requires:** VT_API_KEY

#### Phase 12: Report Generation
**What it does:** Creates comprehensive summary  
**Output:** `reports/SUMMARY_REPORT.txt`  
**Why:** Quick overview of all findings

---

## 🧪 Manual Testing Phase

After automation completes, perform manual testing:

### 1. Test XSS with Loxs

```bash
cd ~/loxs  # Or your loxs path
source venv/bin/activate
python3 loxs.py

# Select: 4 (XSS)
# File: /path/to/bug-hunt-*/xss/loxs_targets.txt
# Payloads: /path/to/loxs/xss_payloads.txt
```

### 2. Test IDOR with Burp + Autorize

```bash
# Setup Burp Suite
# 1. Install Autorize extension (BApp Store)
# 2. Configure two user sessions (low/high privilege)
# 3. Import: bug-hunt-*/idor/api_endpoints.txt
# 4. Browse as high-priv user
# 5. Check Autorize tab for red flags

# Manual ID testing
cat bug-hunt-*/idor/numeric_ids.txt
# Try incrementing/decrementing IDs
# Test: /api/user/123 → /api/user/124
```

### 3. Test SQLi with Loxs

```bash
cd ~/loxs
source venv/bin/activate
python3 loxs.py

# Select: 3 (SQLi)
# File: /path/to/bug-hunt-*/sqli/loxs_targets.txt
# Payloads: /path/to/loxs/generic.txt
```

### 4. Check 404 Files in Wayback (Golden Technique)

```bash
# Review 404 files
cat bug-hunt-*/secrets/404_check_archive.txt

# Example output:
# https://target.com/invoice.pdf|404|CHECK_ARCHIVE:https://web.archive.org/...

# Manual steps:
# 1. Copy Wayback URL
# 2. Paste into browser
# 3. Browse timeline for snapshots
# 4. Download archived files
# 5. Analyze for sensitive data
```

### 5. Download Accessible Files

```bash
# Create download directory
mkdir -p bug-hunt-*/downloaded

# Download all accessible files
wget -i bug-hunt-*/secrets/accessible_files.txt -P bug-hunt-*/downloaded/

# Review for:
# - PII (names, emails, SSNs)
# - Financial data
# - Internal documentation
# - API keys/credentials
```

---

## ⚙️ Advanced Configuration

### Adjust Performance

Edit `master-bug-hunter.sh`:

```bash
# Line 14-16: Performance settings
THREADS=20        # Concurrent operations (increase for faster scans)
RATE_LIMIT=50     # Requests per second (decrease to avoid rate limiting)
```

### Customize Phases

Comment out phases you don't need:

```bash
# Skip Shodan (no API key)
# Line 180-190: Comment out Phase 4

# Skip VirusTotal
# Line 450-460: Comment out Phase 11
```

### Add Custom GF Patterns

```bash
# Create custom pattern
cat > ~/.gf/custom.json << 'EOF'
{
    "flags": "-HanriE",
    "patterns": [
        "custom_param=",
        "internal_id="
    ]
}
EOF

# Use in script (add to Phase 6/7/8)
cat $OUTPUT/all_urls.txt | gf custom > $OUTPUT/custom_targets.txt
```

---

## 📚 Methodology

This framework combines proven methodologies:

### Coffinxp's Techniques
- ✅ Wayback CDX API direct extraction
- ✅ 404 Wayback checking technique
- ✅ XSS pipeline: GF → URO → GXSS → Dalfox
- ✅ Sensitive file categorization
- ✅ Custom GF patterns

### NahamSec's Approach
- ✅ Multi-source subdomain enumeration
- ✅ Deep crawling (Katana)
- ✅ Parameter discovery (Arjun)
- ✅ Organized output structure

### TomNomNom's Tools
- ✅ GF pattern filtering
- ✅ Assetfinder
- ✅ Tool chaining philosophy

### Additional Best Practices
- ✅ URO deduplication (reduces noise)
- ✅ Prioritized findings (high → medium → low)
- ✅ Automated + manual testing hybrid
- ✅ Comprehensive reporting

---

## 🔧 Troubleshooting

### Common Issues

#### Issue: "Command not found: gau/subfinder/etc"

**Solution:**
```bash
# Add Go bin to PATH
export PATH="$HOME/go/bin:$PATH"
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Issue: "externally-managed-environment" (Python)

**Solution:**
```bash
# Use --break-system-packages flag
pip3 install arjun uro --break-system-packages
```

#### Issue: GF patterns not found

**Solution:**
```bash
# Install patterns
git clone https://github.com/coffinxp/GFpattren.git
cp GFpattren/*.json ~/.gf/
rm -rf GFpattren

# Verify
gf -list
```

#### Issue: Out of memory / "Killed"

**Solution:**
```bash
# Add swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Or reduce THREADS in script
# Edit line 14: THREADS=10
```

#### Issue: Loxs not found

**Solution:**
```bash
# Update path in script
sed -i 's|~/loxs|/your/actual/loxs/path|g' ~/bug-bounty-tools/master-bug-hunter.sh

# Or create symlink
ln -s /your/actual/loxs/path ~/loxs
```

#### Issue: Nuclei templates missing

**Solution:**
```bash
# Update templates
nuclei -update-templates

# Verify
ls ~/nuclei-templates/
```

### Getting Help

- Run preflight check: `~/bug-bounty-tools/preflight-check.sh`
- Check logs: Review terminal output for error messages
- Test individual tools: Run each tool manually to isolate issues

---

## 🙏 Credits

### Tools Used
- **[gau](https://github.com/lc/gau)** by @lc - URL collection
- **[subfinder](https://github.com/projectdiscovery/subfinder)** by @projectdiscovery - Subdomain enum
- **[httpx](https://github.com/projectdiscovery/httpx)** by @projectdiscovery - HTTP toolkit
- **[katana](https://github.com/projectdiscovery/katana)** by @projectdiscovery - Web crawler
- **[nuclei](https://github.com/projectdiscovery/nuclei)** by @projectdiscovery - Vuln scanner
- **[arjun](https://github.com/s0md3v/Arjun)** by @s0md3v - Parameter discovery
- **[gf](https://github.com/tomnomnom/gf)** by @tomnomnom - Pattern filtering
- **[uro](https://github.com/s0md3v/uro)** by @s0md3v - URL deduplication
- **[Gxss](https://github.com/KathanP19/Gxss)** by @KathanP19 - Reflected params
- **[dalfox](https://github.com/hahwul/dalfox)** by @hahwul - XSS scanner
- **[loxs](https://github.com/coffinxp/loxs)** by @coffinxp - Vuln testing

### Methodologies
- **[@coffinxp](https://github.com/coffinxp)** - XSS pipeline, 404 technique, GF patterns
- **[@NahamSec](https://github.com/nahamsec)** - Recon methodology
- **[@TomNomNom](https://github.com/tomnomnom)** - Tool ecosystem
- **[@Jhaddix](https://github.com/jhaddix)** - Bug Hunter's Methodology

### Resources
- **[Coffinxp's YouTube](https://www.youtube.com/@coffinxp)**
- **[Coffinxp's Medium](https://coffinxp.medium.com/)**
- **[NahamSec's Twitch](https://www.twitch.tv/nahamsec)**
- **[Bug Bounty Forum](https://bugbountyforum.com/)**

---

## 📄 License

This framework is for **educational and authorized security testing only**.

**⚠️ Warning:**
- Only test on domains you have explicit permission to test
- Respect bug bounty program scopes and rules
- Follow responsible disclosure practices
- Unauthorized testing is illegal

---

## 🎯 Quick Reference

### Essential Commands

```bash
# Install everything
~/bug-bounty-tools/install-all-tools-fixed.sh

# Preflight check
~/bug-bounty-tools/preflight-check.sh

# Run automation
~/bug-bounty-tools/master-bug-hunter.sh targets.txt

# View results
cat bug-hunt-*/reports/SUMMARY_REPORT.txt

# Test with Loxs
cd ~/loxs && source venv/bin/activate && python3 loxs.py
```

### File Locations

```
~/bug-bounty-tools/          # Scripts
~/go/bin/                    # Go tools
~/.gf/                       # GF patterns
~/nuclei-templates/          # Nuclei templates
~/loxs/                      # Loxs tool
bug-hunt-TIMESTAMP/          # Results (created each run)
```

---

**Happy Hunting! 🎯🔍**

For questions, improvements, or issues, refer to the troubleshooting section or the original tool repositories.
