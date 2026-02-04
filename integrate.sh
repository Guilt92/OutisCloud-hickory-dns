#!/bin/bash

# Hickory DNS Manager - Master Integration Script
# Complete setup: PostgreSQL → API → UI → E2E Tests
# Run with: bash integrate.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="/tmp/hickory-logs"
mkdir -p "$LOGS_DIR"

# Logging functions
log_header() { echo -e "\n${CYAN}╔════════════════════════════════════════════════════════╗${NC}"; echo -e "${CYAN}║ $1${NC}"; echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"; }
log_section() { echo -e "\n${BLUE}→ $1${NC}"; }
log_success() { echo -e "${GREEN}  ✓ $1${NC}"; }
log_error() { echo -e "${RED}  ✗ $1${NC}"; exit 1; }
log_info() { echo -e "${YELLOW}  ℹ $1${NC}"; }
log_warn() { echo -e "${YELLOW}  ⚠ $1${NC}"; }

# Cleanup on exit
cleanup() {
  echo ""
  log_info "Cleaning up background processes..."
  kill $(jobs -p) 2>/dev/null || true
  sleep 1
}
trap cleanup EXIT

# ============================================================================
# HEADER
# ============================================================================
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════╗"
echo "║    Hickory DNS Manager - Full Integration Test        ║"
echo "║         PostgreSQL | API | UI | E2E Tests             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================================
# PHASE 1: CHECK PREREQUISITES
# ============================================================================
log_header "PHASE 1: CHECKING PREREQUISITES"

echo -n "  Docker: "
if docker ps > /dev/null 2>&1; then
  log_success "Available and running"
else
  log_error "Docker not available or not running. Please start Docker."
fi

echo -n "  Node.js: "
if command -v node &> /dev/null; then
  NODE_V=$(node --version)
  log_success "Installed ($NODE_V)"
else
  log_error "Node.js not found. Please install Node.js 16+"
fi

echo -n "  Rust: "
if command -v cargo &> /dev/null; then
  CARGO_V=$(cargo --version | cut -d' ' -f1-2)
  log_success "Installed ($CARGO_V)"
else
  log_error "Rust not found. Please install Rust via rustup"
fi

echo -n "  PostgreSQL client: "
if command -v psql &> /dev/null; then
  log_success "Installed"
else
  log_warn "psql not found (optional)"
fi

# ============================================================================
# PHASE 2: SETUP POSTGRESQL
# ============================================================================
log_header "PHASE 2: SETUP POSTGRESQL DATABASE"

log_section "Stopping existing PostgreSQL container..."
docker stop hickory-postgres 2>/dev/null && log_success "Stopped" || log_info "No existing container"
docker rm hickory-postgres 2>/dev/null && log_success "Removed" || true
sleep 1

log_section "Starting PostgreSQL 15..."
if docker run -d \
  --name hickory-postgres \
  --network host \
  -e POSTGRES_DB=hickory \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_INITDB_ARGS="--encoding=UTF8" \
  postgres:15-alpine > "$LOGS_DIR/postgres.log" 2>&1; then
  log_success "PostgreSQL container started"
else
  log_error "Failed to start PostgreSQL container. Check Docker is running."
fi

# Wait for PostgreSQL to be ready
log_section "Waiting for PostgreSQL to accept connections..."
for i in {1..30}; do
  if nc -z localhost 5432 2>/dev/null; then
    log_success "PostgreSQL is ready"
    break
  fi
  if [ $i -eq 30 ]; then
    log_error "PostgreSQL failed to start after 30 seconds"
  fi
  echo -n "."
  sleep 1
done
echo ""

# ============================================================================
# PHASE 3: BUILD AND RUN API
# ============================================================================
log_header "PHASE 3: BUILD AND RUN RUST API"

export DATABASE_URL="postgres://postgres:password@localhost:5432/hickory?sslmode=disable"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="admin123"
export JWT_SECRET="dev-secret-key-change-in-production"
export RUST_LOG="info"


cd "$ROOT_DIR/crates/control_api"


log_section "Building Control API (release mode)..."
log_info "This may take 3-5 minutes on first run..."
if ! cargo build --release > "$LOGS_DIR/build.log" 2>&1; then
  log_error "API build failed. Check $LOGS_DIR/build.log"
fi
log_success "API built successfully"

log_section "Starting API on port 8080..."
nohup ./target/release/control_api > "$LOGS_DIR/api.log" 2>&1 &
API_PID=$!
echo $API_PID > "$LOGS_DIR/api.pid"
log_success "API process started (PID: $API_PID)"

# Wait for API to be ready
log_section "Waiting for API health check..."
for i in {1..90}; do
  if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    log_success "API is ready"
    break
  fi
  if [ $i -eq 90 ]; then
    log_warn "API health check timeout after 90 seconds (may still be initializing)"
  fi
  echo -n "."
  sleep 1
done
echo ""

# ============================================================================
# PHASE 4: SETUP AND START UI
# ============================================================================
log_header "PHASE 4: SETUP AND START REACT UI"

cd "$ROOT_DIR/web/ui"


if [ ! -d "node_modules" ]; then
  log_section "Installing UI dependencies..."
  log_info "This may take 1-2 minutes..."
  if ! npm install > "$LOGS_DIR/npm-install.log" 2>&1; then
    log_warn "npm install had issues (see $LOGS_DIR/npm-install.log)"
  fi
  log_success "Dependencies installed"
else
  log_success "Dependencies already installed"
fi

log_section "Starting UI dev server on port 3000..."
nohup npm run dev > "$LOGS_DIR/ui.log" 2>&1 &
UI_PID=$!
echo $UI_PID > "$LOGS_DIR/ui.pid"
log_success "UI process started (PID: $UI_PID)"

# Wait for UI to be ready
log_section "Waiting for UI to respond..."
for i in {1..90}; do
  if curl -s http://localhost:3000 > /dev/null 2>&1; then
    log_success "UI is ready"
    break
  fi
  if [ $i -eq 90 ]; then
    log_warn "UI startup timeout after 90 seconds"
  fi
  echo -n "."
  sleep 1
done
echo ""

# ============================================================================
# PHASE 5: RUN E2E TESTS (Optional)
# ============================================================================
if [ -f "tests/e2e.spec.ts" ] || [ -d "tests" ]; then
  log_header "PHASE 5: E2E TESTS"
  
  log_section "Running Playwright E2E tests..."
  log_info "This may take 5-10 minutes..."
  
  if npm run test:e2e > "$LOGS_DIR/e2e-tests.log" 2>&1; then
    log_success "All E2E tests passed!"
  else
    log_warn "Some E2E tests failed (see $LOGS_DIR/e2e-tests.log for details)"
  fi
else
  log_section "E2E tests not found, skipping..."
fi

# ============================================================================
# FINAL REPORT
# ============================================================================
log_header "✅ INTEGRATION COMPLETE"

echo ""
echo -e "${GREEN}Services are running:${NC}"
echo ""

if ps -p $(cat "$LOGS_DIR/api.pid" 2>/dev/null) > /dev/null 2>&1; then
  echo -e "  ${GREEN}✓${NC} API running on http://localhost:8080"
else
  echo -e "  ${RED}✗${NC} API not running"
fi

if ps -p $(cat "$LOGS_DIR/ui.pid" 2>/dev/null) > /dev/null 2>&1; then
  echo -e "  ${GREEN}✓${NC} UI running on http://localhost:3000"
else
  echo -e "  ${RED}✗${NC} UI not running"
fi

if docker ps 2>/dev/null | grep -q "hickory-postgres"; then
  echo -e "  ${GREEN}✓${NC} PostgreSQL running on localhost:5432"
else
  echo -e "  ${RED}✗${NC} PostgreSQL not running"
fi

echo ""
echo -e "${CYAN}Access the application:${NC}"
echo "  URL: http://localhost:3000"
echo "  Username: admin"
echo "  Password: admin123"
echo ""

echo -e "${CYAN}Service logs:${NC}"
echo "  API: tail -f $LOGS_DIR/api.log"
echo "  UI: tail -f $LOGS_DIR/ui.log"
echo "  PostgreSQL: tail -f $LOGS_DIR/postgres.log"
echo ""

echo -e "${CYAN}Stop services:${NC}"
echo "  Press Ctrl+C or run: bash stop-services.sh"
echo ""

# Keep services running
log_info "Services will continue running. Press Ctrl+C to stop."
wait
