# Run tests in Docker container (Linux) to avoid Windows pprof/nix issues

Write-Host "Building Docker test image..." -ForegroundColor Cyan
docker build -f Dockerfile.test -t sonobe-fflonk-test .

Write-Host ""
Write-Host "Running tests..." -ForegroundColor Cyan
docker run --rm sonobe-fflonk-test

Write-Host ""
Write-Host "Tests completed successfully!" -ForegroundColor Green
