#!/bin/bash

echo "Installing all bug bounty tools (FIXED VERSION)..."

# Fix Kali repositories first
echo "[1/5] Fixing Kali repositories..."
echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee /etc/apt/sources.list
sudo apt clean
sudo apt update --fix-missing

# Core tools (skip jq if it fails, not critical)
echo "[2/5] Installing core tools..."
sudo apt install -y curl wget git golang-go python3 python3-pip python3-venv 2>/dev/null || true

# Try to install jq separately
sudo apt install -y jq 2>/dev/null || echo "jq install skipped (optional)"

# Go tools
echo "[3/5] Installing Go tools (this takes a few minutes)..."
export PATH="$HOME/go/bin:$PATH"

go install github.com/lc/gau/v2/cmd/gau@latest &
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &
go install github.com/tomnomnom/assetfinder@latest &
go install github.com/projectdiscovery/httpx/cmd/httpx@latest &
wait

go install github.com/projectdiscovery/katana/cmd/katana@latest &
go install github.com/tomnomnom/gf@latest &
go install github.com/KathanP19/Gxss@latest &
go install github.com/hahwul/dalfox/v2@latest &
wait

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
wait

# Python tools (use pipx to avoid externally managed environment)
echo "[4/5] Installing Python tools..."

# Install pipx if not present
if ! command -v pipx &> /dev/null; then
    python3 -m pip install --user pipx --break-system-packages 2>/dev/null || \
    python3 -m pip install --user pipx
    python3 -m pipx ensurepath
fi

# Install Python tools via pipx
pipx install arjun 2>/dev/null || pip3 install arjun --break-system-packages
pipx install uro 2>/dev/null || pip3 install uro --break-system-packages

# Update nuclei templates
echo "[5/5] Setting up templates and patterns..."
$HOME/go/bin/nuclei -update-templates 2>/dev/null || true

# Setup GF patterns
mkdir -p ~/.gf
if [ ! -d "/tmp/GFpattren" ]; then
    git clone https://github.com/coffinxp/GFpattren.git /tmp/GFpattren 2>/dev/null || true
    cp /tmp/GFpattren/*.json ~/.gf/ 2>/dev/null || true
    rm -rf /tmp/GFpattren
fi

# Add Go bin to PATH permanently
if ! grep -q 'export PATH="$HOME/go/bin:$PATH"' ~/.bashrc; then
    echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
fi

if ! grep -q 'export PATH="$HOME/go/bin:$PATH"' ~/.zshrc 2>/dev/null; then
    echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc 2>/dev/null || true
fi

# Source the updated PATH
export PATH="$HOME/go/bin:$PATH"

echo ""
echo "✓ Installation complete!"
echo ""
echo "Run these commands:"
echo "  source ~/.bashrc"
echo "  ~/preflight-check.sh"
