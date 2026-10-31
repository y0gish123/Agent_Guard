#!/usr/bin/env bash
# Start AgentGuard mock tool and backend services in guarded or naive mode
set -e

MODE="${1:-guarded}"
if [[ "$MODE" != "guarded" && "$MODE" != "naive" ]]; then
  echo "Usage: ./scripts/dev_up.sh [guarded|naive]"
  exit 1
fi

export DEMO_MODE="$MODE"
export SIMULATION="true"

echo "=========================================================="
echo " Starting AgentGuard AI SOC in [$MODE] mode"
echo " Mock Tool: http://localhost:8001"
echo " Backend:   http://localhost:8000"
echo " Press Ctrl+C to terminate both servers"
echo "=========================================================="

python -m uvicorn mock_tool.app:app --port 8001 --reload &
TOOL_PID=$!

python -m uvicorn backend.main:app --port 8000 --reload &
BACKEND_PID=$!

trap "kill $TOOL_PID $BACKEND_PID 2>/dev/null || true; echo 'Shutting down AgentGuard services...'; exit 0" SIGINT SIGTERM EXIT

wait

