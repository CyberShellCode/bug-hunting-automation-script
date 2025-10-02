#!/bin/bash

#############################################
# Preflight Check for Bug Bounty Automation
# Verifies all required tools are installed
#############################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
WARN=0

# Arrays to store results
declare -a FAILED_TOOLS
declare -a MISSING_TOOLS
declare -a WARNING_ITEMS

echo -e "${BLUE}"
cat << "EOF"
╔════════════════════════════════════════════════╗
║     BUG BOUNTY TOOLS PREFLIGHT CHECK          ║
╚════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Function to check if command exists
check_tool() {
    local tool=$1
    local install_cmd=$2
    
    if command -v "$tool" &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} $tool is installed"
        ((PASS++))
        
        # Try to get version
        case $tool in
            gau|subfinder|httpx|katana|nuclei|arjun|dalfox|gf)
                version=$("$tool" --version 2>/dev/null || "$tool" -version 2>/dev/null || echo "version unknown")
                echo -e "    ${BLUE}→${NC} $version"
                ;;
        esac
        return 0
    else
        echo -e "${RED}[✗]${NC} $tool is NOT installed"
        echo -e "    ${YELLOW}Install:${NC} $install_cmd"
        FAILED_TOOLS+=("$tool")
        MISSING_TOOLS+=("$install_cmd")
        ((FAIL++))
        return 1
    fi
}

# Function to check Python package
check_python_package() {
    local package=$1
    local install_cmd=$2
    
    if python3 -c "import $package" 2>/dev/null; then
        echo -e "${GREEN}[✓]${NC} Python package: $package"
        ((PASS++))
        return 0
    else
        echo -e "${RED}[✗]${NC} Python package: $package is NOT installed"
        echo -e "    ${YELLOW}Install:${NC} $install_cmd"
        FAILED_TOOLS+=("$package")
        MISSING_TOOLS+=("$install_cmd")
        ((FAIL++))
        return 1
    fi
}

# Function to check file/directory
check_path() {
    local path=$1
    local description=$2
    
    if [ -e "$path" ]; then
        echo -e "${GREEN}[✓]${NC} $description: $path"
        ((PASS++))
        return 0
    else
        echo -e "${YELLOW}[!]${NC} $description: $path NOT found"
        WARNING_ITEMS+=("$description")
        ((WARN++))
        return 1
    fi
}

# Function to check optional API key
check_api_key() {
    local key_name=$1
    local key_value=$2
    
    if [ -n "$key_value" ]; then
        echo -e "${GREEN}[✓]${NC} $key_name is set"
        ((PASS++))
        return 0
    else
        echo -e "${YELLOW}[!]${NC} $key_name is NOT set (optional)"
        echo -e "    ${BLUE}Info:${NC} Some features will be skipped without this key"
        WARNING_ITEMS+=("$key_name not set")
        ((WARN++))
        return 1
    fi
}

echo -e "${CYAN}━━━ Core Tools ━━━${NC}"
check_tool "curl" "sudo apt install curl"
check_tool "wget" "sudo apt install wget"
check_tool "git" "sudo apt install git"
check_tool "jq" "sudo apt install jq"
check_tool "python3" "sudo apt install python3"
check_tool "pip3" "sudo apt install python3-pip"
check_tool "go" "sudo apt install golang-go"

echo -e "\n${CYAN}━━━ Recon Tools ━━━${NC}"
check_tool "gau" "go install github.com/lc/gau/v2/cmd/gau@latest"
check_tool "subfinder" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_tool "assetfinder" "go install github.com/tomnomnom/assetfinder@latest"
check_tool "httpx" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_tool "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest"

echo -e "\n${CYAN}━━━ Parameter Discovery ━━━${NC}"
check_tool "arjun" "pip3 install arjun"
check_tool "gf" "go install github.com/tomnomnom/gf@latest"

echo -e "\n${CYAN}━━━ XSS Tools ━━━${NC}"
check_python_package "uro" "pip3 install uro"
check_tool "Gxss" "go install github.com/KathanP19/Gxss@latest"
check_tool "dalfox" "go install github.com/hahwul/dalfox/v2@latest"

echo -e "\n${CYAN}━━━ Vulnerability Scanner ━━━${NC}"
check_tool "nuclei" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

echo -e "\n${CYAN}━━━ Custom Tools ━━━${NC}"
check_path "$HOME/loxs" "Loxs tool directory"
if [ -d "$HOME/loxs" ]; then
    check_path "$HOME/loxs/loxs.py" "Loxs main script"
    check_path "$HOME/loxs/venv" "Loxs virtual environment"
fi

echo -e "\n${CYAN}━━━ GF Patterns ━━━${NC}"
check_path "$HOME/.gf" "GF patterns directory"
if [ -d "$HOME/.gf" ]; then
    pattern_count=$(ls -1 "$HOME/.gf"/*.json 2>/dev/null | wc -l)
    if [ "$pattern_count" -gt 0 ]; then
        echo -e "${GREEN}[✓]${NC} Found $pattern_count GF pattern files"
        ((PASS++))
    else
        echo -e "${YELLOW}[!]${NC} No GF pattern files found in ~/.gf/"
        echo -e "    ${YELLOW}Install:${NC} git clone https://github.com/coffinxp/GFpattren.git && cp GFpattren/*.json ~/.gf/"
        WARNING_ITEMS+=("GF patterns missing")
        ((WARN++))
    fi
fi

echo -e "\n${CYAN}━━━ Nuclei Templates ━━━${NC}"
nuclei_templates="$HOME/nuclei-templates"
check_path "$nuclei_templates" "Nuclei templates directory"
if [ -d "$nuclei_templates" ]; then
    template_count=$(find "$nuclei_templates" -name "*.yaml" 2>/dev/null | wc -l)
    echo -e "${GREEN}[✓]${NC} Found $template_count nuclei templates"
    ((PASS++))
fi

echo -e "\n${CYAN}━━━ Go Binary Path ━━━${NC}"
check_path "$HOME/go/bin" "Go binaries directory"
if [ -d "$HOME/go/bin" ]; then
    if [[ ":$PATH:" == *":$HOME/go/bin:"* ]]; then
        echo -e "${GREEN}[✓]${NC} Go bin directory is in PATH"
        ((PASS++))
    else
        echo -e "${YELLOW}[!]${NC} Go bin directory is NOT in PATH"
        echo -e "    ${YELLOW}Fix:${NC} echo 'export PATH=\"\$HOME/go/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
        WARNING_ITEMS+=("Go bin not in PATH")
        ((WARN++))
    fi
fi

echo -e "\n${CYAN}━━━ API Keys (Optional) ━━━${NC}"
check_api_key "SHODAN_API_KEY" "$SHODAN_API_KEY"
check_api_key "VT_API_KEY" "$VT_API_KEY"

echo -e "\n${CYAN}━━━ Testing Basic Functionality ━━━${NC}"

# Test gau
if command -v gau &> /dev/null; then
    echo -n -e "${BLUE}[→]${NC} Testing gau... "
    if timeout 5 gau --help &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAILED${NC}"
        ((FAIL++))
    fi
fi

# Test subfinder
if command -v subfinder &> /dev/null; then
    echo -n -e "${BLUE}[→]${NC} Testing subfinder... "
    if timeout 5 subfinder --help &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAILED${NC}"
        ((FAIL++))
    fi
fi

# Test httpx
if command -v httpx &> /dev/null; then
    echo -n -e "${BLUE}[→]${NC} Testing httpx... "
    if timeout 5 httpx --help &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAILED${NC}"
        ((FAIL++))
    fi
fi

# Test nuclei
if command -v nuclei &> /dev/null; then
    echo -n -e "${BLUE}[→]${NC} Testing nuclei... "
    if timeout 5 nuclei --help &> /dev/null; then
        echo -e "${GREEN}OK${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAILED${NC}"
        ((FAIL++))
    fi
fi

# Test gf patterns
if command -v gf &> /dev/null; then
    echo -n -e "${BLUE}[→]${NC} Testing gf patterns... "
    pattern_list=$(gf -list 2>/dev/null)
    if [ -n "$pattern_list" ]; then
        echo -e "${GREEN}OK${NC} ($(echo "$pattern_list" | wc -w) patterns)"
        ((PASS++))
    else
        echo -e "${YELLOW}WARN${NC} (no patterns found)"
        ((WARN++))
    fi
fi

# Test loxs
if [ -f "$HOME/loxs/loxs.py" ]; then
    echo -n -e "${BLUE}[→]${NC} Testing loxs... "
    cd "$HOME/loxs" 2>/dev/null
    if [ -d "venv" ]; then
        source venv/bin/activate 2>/dev/null
        if python3 -c "import selenium, webdriver_manager" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
            ((PASS++))
        else
            echo -e "${YELLOW}WARN${NC} (dependencies may be missing)"
            ((WARN++))
        fi
        deactivate 2>/dev/null
    else
        echo -e "${YELLOW}WARN${NC} (venv not found)"
        ((WARN++))
    fi
    cd - > /dev/null 2>&1
fi

echo -e "\n${CYAN}━━━ System Resources ━━━${NC}"

# Check memory
total_mem=$(free -m | awk '/^Mem:/{print $2}')
echo -e "${BLUE}[→]${NC} Total RAM: ${total_mem}MB"
if [ "$total_mem" -lt 2000 ]; then
    echo -e "${YELLOW}[!]${NC} Low memory detected. Consider adding swap or limiting threads."
    ((WARN++))
else
    echo -e "${GREEN}[✓]${NC} Sufficient memory"
    ((PASS++))
fi

# Check disk space
free_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
echo -e "${BLUE}[→]${NC} Free disk space: ${free_space}GB"
if [ "$free_space" -lt 5 ]; then
    echo -e "${YELLOW}[!]${NC} Low disk space. Results may require significant storage."
    ((WARN++))
else
    echo -e "${GREEN}[✓]${NC} Sufficient disk space"
    ((PASS++))
fi

# Check internet connectivity
echo -n -e "${BLUE}[→]${NC} Testing internet connectivity... "
if curl -s --connect-timeout 5 https://www.google.com > /dev/null; then
    echo -e "${GREEN}OK${NC}"
    ((PASS++))
else
    echo -e "${RED}FAILED${NC} (no internet connection)"
    ((FAIL++))
fi

# Summary
echo -e "\n${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              PREFLIGHT CHECK SUMMARY           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}Passed:${NC}   $PASS"
echo -e "${RED}Failed:${NC}   $FAIL"
echo -e "${YELLOW}Warnings:${NC} $WARN"

TOTAL=$((PASS + FAIL + WARN))
PERCENTAGE=$((PASS * 100 / TOTAL))

echo -e "\n${BLUE}Success Rate:${NC} ${PERCENTAGE}%"

# Final verdict
if [ "$FAIL" -eq 0 ]; then
    echo -e "\n${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ ALL CRITICAL TOOLS ARE READY!              ║${NC}"
    echo -e "${GREEN}║  You can run the master automation script.    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}\n"
    
    if [ "$WARN" -gt 0 ]; then
        echo -e "${YELLOW}Note: Some optional features may be limited due to warnings above.${NC}\n"
    fi
    
    exit 0
else
    echo -e "\n${RED}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ CRITICAL TOOLS ARE MISSING!                 ║${NC}"
    echo -e "${RED}║  Please install missing tools before running. ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}Quick Fix - Install All Missing Tools:${NC}\n"
    
    # Generate install script
    cat > /tmp/install_missing_tools.sh << 'INSTALLEOF'
#!/bin/bash
echo "Installing missing tools..."

# Go tools
INSTALLEOF
    
    for tool in "${FAILED_TOOLS[@]}"; do
        for cmd in "${MISSING_TOOLS[@]}"; do
            if [[ "$cmd" == *"$tool"* ]]; then
                echo "$cmd" >> /tmp/install_missing_tools.sh
            fi
        done
    done
    
    echo 'echo "Installation complete! Run preflight check again."' >> /tmp/install_missing_tools.sh
    chmod +x /tmp/install_missing_tools.sh
    
    echo -e "${GREEN}[Generated]${NC} Installation script: /tmp/install_missing_tools.sh"
    echo -e "${YELLOW}Run:${NC} bash /tmp/install_missing_tools.sh\n"
    
    # Show install commands
    echo -e "${YELLOW}Or install manually:${NC}"
    for cmd in "${MISSING_TOOLS[@]}"; do
        echo -e "  ${BLUE}→${NC} $cmd"
    done
    echo ""
    
    exit 1
fi
