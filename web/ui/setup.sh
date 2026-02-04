#!/bin/bash
set -e

echo "=== Hickory DNS UI Setup ==="

# Ensure Postgres is running
echo "Checking/starting Postgres container..."
if ! docker ps | grep -q hickory-postgres; then
  if docker ps -a | grep -q hickory-postgres; then
    echo "Starting existing container..."
    docker start hickory-postgres
  else
    echo "Creating new Postgres container..."
    docker run -d --name hickory-postgres -e POSTGRES_PASSWORD=password -p 5432:5432 postgres:15
  fi
fi

# Wait for Postgres to be ready
echo "Waiting for Postgres to be ready..."
for i in {1..30}; do
  if docker exec hickory-postgres psql -U postgres -c "SELECT 1" > /dev/null 2>&1; then
    echo "Postgres is ready!"
    break
  fi
  echo "Attempt $i/30..."
  sleep 1
done

# Create hickory database
echo "Creating hickory database..."
docker exec hickory-postgres psql -U postgres -c "CREATE DATABASE hickory;" 2>&1 || echo "Database may already exist"

echo "=== Database setup complete ==="
