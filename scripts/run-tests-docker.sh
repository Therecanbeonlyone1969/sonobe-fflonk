#!/bin/bash
# Run tests in Docker container (Linux) to avoid Windows pprof/nix issues

set -e

echo "Building Docker test image..."
docker build -f Dockerfile.test -t sonobe-fflonk-test .

echo ""
echo "Running tests..."
docker run --rm sonobe-fflonk-test

echo ""
echo "Tests completed successfully!"
