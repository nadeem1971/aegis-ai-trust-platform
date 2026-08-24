#!/usr/bin/env bash
# One-time Codespace setup: Postgres, Python deps, test DB.
set -e
echo "── Starting local PostgreSQL (docker compose) ──"
cd services/gateway
docker compose up -d
sleep 5

echo "── Installing gateway dependencies ──"
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install presidio-analyzer presidio-anonymizer

echo "── Creating test database ──"
until docker compose exec -T postgres pg_isready -U aegis; do sleep 1; done
docker compose exec -T postgres psql -U aegis -d aegis -c "CREATE DATABASE aegis_test;" || true

echo "── Preparing .env ──"
if [ ! -f .env ]; then cp .env.example .env; fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  AEGIS Codespace ready."
echo ""
echo "  Run the tests:      cd services/gateway && python -m pytest"
echo "  Run the demo:       python demo_week3.py   (from repo root)"
echo ""
echo "  Live server needs Azure login + OPENAI_ENDPOINT in .env:"
echo "    az login --use-device-code"
echo "    # set OPENAI_ENDPOINT=https://safewatch-openai.openai.azure.com/"
echo "    cd services/gateway && python -m uvicorn app.main:app --host 0.0.0.0"
echo "════════════════════════════════════════════════════════════"
