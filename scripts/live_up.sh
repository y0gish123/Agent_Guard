#!/usr/bin/env bash
# Start AgentGuard in LIVE mode (Mock Tool, Stub Site, Backend, and Collector)
MODE="${1:-guarded}"

export DEMO_MODE="$MODE"
export LIVE_MODE="true"
export SIMULATION="true"
export TOOL_BACKEND="portal"

echo "=========================================================="
echo " Starting AgentGuard AI SOC in LIVE [$MODE] mode"
echo " Mock Tool (Portal mode): http://localhost:8001"
echo " Stub Victim Clinic Site: http://localhost:8002"
echo " SOC Backend:             http://localhost:8000"
echo " Collector:               Tailing site logs -> Backend"
echo "=========================================================="

SITE_DEMO=true python -m uvicorn testbed.stub_site.main:app --port 8002 --reload &
SITE_PID=$!

python -m uvicorn mock_tool.app:app --port 8001 --reload &
TOOL_PID=$!

python -m uvicorn backend.main:app --port 8000 --reload &
BACKEND_PID=$!

sleep 2
python collector/collector.py &
COLLECTOR_PID=$!

echo "Services started. Site PID: $SITE_PID, Tool PID: $TOOL_PID, Backend PID: $BACKEND_PID, Collector PID: $COLLECTOR_PID"
wait

