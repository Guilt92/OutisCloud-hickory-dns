#!/bin/bash

# Quick diagnostic script to check system readiness

echo "🔍 Hickory DNS Manager - System Readiness Check"
echo "=================================================="
echo ""

# Check Docker
echo "✓ Checking Docker..."
if command -v docker &> /dev/null; then
  if docker ps > /dev/null 2>&1; then
    DOCKER_VERSION=$(docker --version)
    echo "  ✓ Docker is running: $DOCKER_VERSION"
  else
    echo "  ✗ Docker daemon is not running"
    echo "    Start Docker and try again"
  fi
else
  echo "  ✗ Docker not found"
  echo "    Install Docker: https://docs.docker.com/get-docker/"
fi

echo ""

# Check Node.js
echo "✓ Checking Node.js..."
if command -v node &> /dev/null; then
  NODE_VERSION=$(node --version)
  NPM_VERSION=$(npm --version)
  echo "  ✓ Node.js: $NODE_VERSION"
  echo "  ✓ npm: $NPM_VERSION"
else
  echo "  ✗ Node.js not found"
  echo "    Install Node.js 16+: https://nodejs.org/"
fi

echo ""

# Check Rust
echo "✓ Checking Rust..."
if command -v rustc &> /dev/null; then
  RUST_VERSION=$(rustc --version)
  CARGO_VERSION=$(cargo --version)
  echo "  ✓ Rustc: $RUST_VERSION"
  echo "  ✓ Cargo: $CARGO_VERSION"
else
  echo "  ✗ Rust not found"
  echo "    Install Rust: https://rustup.rs/"
fi

echo ""

# Check critical files
echo "✓ Checking project files..."
FILES_OK=0
TOTAL_FILES=0

check_file() {
  TOTAL_FILES=$((TOTAL_FILES + 1))
  if [ -f "$1" ]; then
    echo "  ✓ $1"
    FILES_OK=$((FILES_OK + 1))
  else
    echo "  ✗ $1 (not found)"
  fi
}

check_file ".//run_complete_integration.sh"
check_file "./web/ui/package.json"
check_file ".//crates/control_api/Cargo.toml"

echo ""
echo "=================================================="

# Summary
if [ "$FILES_OK" -eq "$TOTAL_FILES" ]; then
  echo "✅ System is ready for integration test!"
  echo ""
  echo "To start the complete integration test, run:"
  echo "  bash .//run_complete_integration.sh"
else
  echo "⚠️  Some components are missing. Check above for details."
fi
