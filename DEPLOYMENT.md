# Production Deployment Guide

This repository is deployment-ready using container images and a production compose stack.

## Prerequisites

1. Docker Engine with Compose plugin.
2. Public DNS names and TLS termination at your ingress/load balancer.
3. Strong production secrets.

## Deploy Steps

1. Create production env file:

   cp .env.production.compose.example .env.production

2. Edit `.env.production` and set required secure values:

   - `POSTGRES_PASSWORD`
   - `SESSION_TOKEN_SIGNING_KEYS`
   - `CORS_ALLOW_ORIGINS`

3. Start stack:

   docker compose --env-file .env.production -f docker-compose.production.yml up -d --build

   Or use the wrapper script:

   ./scripts/startprod.sh

4. Verify health:

   - API: `http://127.0.0.1:8000/health`
   - UI: `http://127.0.0.1:4173`

## Security Defaults Included

1. Backend runs with `APP_ENV=production` and disables startup schema auto-create by default.
2. Header-based actor auth is disabled in production.
3. Redis-backed distributed rate limiting is configured.
4. Frontend is served by a Python static server with strict browser security headers (nginx deprecated).
5. Containers include health checks and restart policies.

## Scale and Hardening Notes

1. Set `UVICORN_WORKERS` based on CPU cores.
2. Run database migrations before rolling deployments.
3. Terminate TLS at ingress and restrict service exposure to required ports.
4. Store secrets in a secret manager and inject at runtime.
5. Enable centralized log shipping and alerting for `/health`, rate-limit degradation, and auth failures.

## Stop Stack

docker compose --env-file .env.production -f docker-compose.production.yml down

Or use wrapper scripts:

./scripts/stopprod.sh
./scripts/statusprod.sh
