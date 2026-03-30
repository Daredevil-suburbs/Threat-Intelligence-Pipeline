#!/usr/bin/env bash
# setup_linux.sh — Threat Intelligence Pipeline setup for Linux/WSL
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

echo ""
echo "============================================"
echo " Threat Intelligence Pipeline — Linux Setup"
echo "============================================"
echo ""

# ── Check Python ─────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    info "Installing Python3..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi
ok "Python3 found: $(python3 --version)"

# ── Check Docker ─────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    warn "Docker not found. Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    warn "Added $USER to docker group. You may need to log out and back in."
fi
ok "Docker found: $(docker --version)"

if ! command -v docker compose version &>/dev/null 2>&1; then
    warn "docker compose not found. Trying docker-compose..."
    COMPOSE_CMD="docker-compose"
else
    COMPOSE_CMD="docker compose"
fi

# ── Increase vm.max_map_count for Elasticsearch ───────────────
CURRENT=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$CURRENT" -lt 262144 ]; then
    info "Setting vm.max_map_count for Elasticsearch..."
    sudo sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf >/dev/null
    ok "vm.max_map_count set to 262144"
else
    ok "vm.max_map_count already sufficient ($CURRENT)"
fi

# ── .env file ─────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    ok ".env created from template"
else
    ok ".env already exists"
fi

# ── Python virtualenv ─────────────────────────────────────────
if [ ! -d venv ]; then
    info "Creating Python virtual environment..."
    python3 -m venv venv
fi
ok "Virtual environment ready"

info "Installing Python dependencies..."
source venv/bin/activate
pip install -r requirements.txt --quiet
ok "Dependencies installed"

# ── Directories ───────────────────────────────────────────────
mkdir -p logs data reports/output
ok "Directories created"

# ── Start Elastic Stack ───────────────────────────────────────
info "Starting Elasticsearch + Kibana via Docker..."
info "(First run pulls ~1.5GB images — be patient)"
$COMPOSE_CMD up -d
ok "Docker containers started"

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo "  Next steps:"
echo "  1. Wait ~60s for Elasticsearch to start"
echo "  2. Activate venv: source venv/bin/activate"
echo "  3. Run pipeline:  python3 main.py"
echo ""
echo "  Kibana Dashboard:  http://localhost:5601"
echo "  Elasticsearch:     http://localhost:9200"
echo ""
