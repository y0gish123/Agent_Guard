#!/usr/bin/env bash
# Reset backend and mock tool, then seed all demonstration scenarios
set -e

BASE_URL="${1:-http://localhost:8000}"

echo "Resetting backend and mock tool via $BASE_URL/api/demo/reset..."
curl -s -X POST "$BASE_URL/api/demo/reset" || echo "Reset request failed"
echo ""

echo "Seeding scenario 'all' via $BASE_URL/api/demo/seed?scenario=all..."
curl -s -X POST "$BASE_URL/api/demo/seed?scenario=all" || echo "Seed request failed"
echo ""

echo "Current Funnel metrics:"
curl -s "$BASE_URL/api/funnel" || true
echo ""

