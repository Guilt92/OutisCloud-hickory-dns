#!/bin/bash
set -e

echo "=== Starting Hickory DNS UI ==="
cd ./web/ui

# Install dependencies if needed
if [ ! -d node_modules ]; then
  echo "Installing npm dependencies..."
  npm install
fi

# Install Playwright browsers if needed
if [ ! -d ~/.cache/ms-playwright ]; then
  echo "Installing Playwright browsers..."
  npm run e2e:install
fi

echo "=== Starting dev server on port 3000 ==="
npm run dev -- --port 3000
