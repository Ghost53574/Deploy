#!/bin/bash
# Setup script for the Integrated Deploy, Bottering, and Booter solution
# This script installs dependencies and configures the environment

set -e # Exit on error

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   Deploy Setup   ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Check if running as root and warn
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${YELLOW}WARNING: Running as root. It's recommended to run as a regular user with sudo access.${NC}"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Setup aborted.${NC}"
        exit 1
    fi
fi

# Create necessary directories
echo -e "${GREEN}Creating directory structure...${NC}"
mkdir -p scripts
mkdir -p configs

# Check Python version
echo -e "${GREEN}Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
if [[ ! $python_version =~ ^3\.[6-9] && ! $python_version =~ ^3\.[1-9][0-9] ]]; then
    echo -e "${RED}Error: Python 3.6+ is required. Found: $python_version${NC}"
    exit 1
fi
echo -e "${BLUE}Python version: $python_version${NC}"

# Install dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
python3 -m pip install --upgrade pip --user --break-system-packages
python3 -m pip install -r requirements.txt --user --break-system-packages

# Create a test configuration file if it doesn't exist
if [ ! -f "configs/test_config.json" ]; then
    echo -e "${GREEN}Creating test configuration file...${NC}"
    cat > configs/test_config.json << 'EOL'
{
  "localhost": {
    "username": "$(whoami)",
    "password": "",
    "os": "linux",
    "address": "127.0.0.1",
    "port": "22"
  }
}
EOL
    echo -e "${YELLOW}A test configuration was created at configs/test_config.json${NC}"
    echo -e "${YELLOW}Edit this file to add your actual hosts and credentials${NC}"
fi

# Create a sample CSV file for testing
if [ ! -f "configs/test_targets.csv" ]; then
    echo -e "${GREEN}Creating test CSV file...${NC}"
    cat > configs/test_targets.csv << 'EOL'
hostname,os,ip,tcp_ports,username,password,purpose,notes
localhost,linux,127.0.0.1,22,$(whoami),,Test host,Local testing
EOL
    echo -e "${YELLOW}A test CSV file was created at configs/test_targets.csv${NC}"
    echo -e "${YELLOW}Edit this file to add your actual targets${NC}"
fi

# Create a test script if scripts directory is empty
if [ ! "$(ls -A scripts)" ]; then
    echo -e "${GREEN}Creating test script...${NC}"
    cat > scripts/test.sh << 'EOL'
#!/bin/bash
# Test script for deploy.py
echo "Hello from $(hostname)"
echo "Current user: $(whoami)"
echo "Current directory: $(pwd)"
EOL
    chmod +x scripts/test.sh
    echo -e "${YELLOW}A test script was created at scripts/test.sh${NC}"
fi

# Set appropriate permissions
echo -e "${GREEN}Setting permissions...${NC}"
chmod +x deploy.py

echo -e "${BLUE}====================================================${NC}"
echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}Example commands:${NC}"
echo -e "  # List available hosts from JSON config:"
echo -e "  python3 deploy.py -j configs/test_config.json -L"
echo -e ""
echo -e "  # Execute test script on local host:"
echo -e "  python3 deploy.py -j configs/test_config.json -t test.sh"
echo -e ""
echo -e "  # List available hosts from CSV:"
echo -e "  python3 deploy.py -c configs/test_targets.csv -L"
echo -e "${BLUE}====================================================${NC}"
