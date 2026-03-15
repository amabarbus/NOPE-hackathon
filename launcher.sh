#!/bin/bash
# Nuke old processes
pkill -f "python run.py"
pkill -f "python demo/partner_site/app.py"
pkill -f "python demo/traffic_generator.py"
sleep 2

echo "🚀 Starting NOPE! Hub on 8080..."
./venv/bin/python run.py > hub.log 2>&1 &
HUB_PID=$!

echo "🚀 Starting Partner Site on 9000..."
./venv/bin/python demo/partner_site/app.py > partner.log 2>&1 &
PARTNER_PID=$!

echo "🚀 Starting Live Traffic Generator..."
./venv/bin/python demo/traffic_generator.py > generator.log 2>&1 &
GEN_PID=$!

sleep 5

if ps -p $HUB_PID > /dev/null
then
   echo "✅ Hub is running (PID: $HUB_PID)"
else
   echo "❌ Hub failed to start. Check hub.log"
fi

if ps -p $PARTNER_PID > /dev/null
then
   echo "✅ Partner Site is running (PID: $PARTNER_PID)"
else
   echo "❌ Partner Site failed to start. Check partner.log"
fi

if ps -p $GEN_PID > /dev/null
then
   echo "✅ Traffic Generator is running (PID: $GEN_PID)"
else
   echo "❌ Traffic Generator failed to start. Check generator.log"
fi

echo ""
echo "Dashboard: http://localhost:8080/dashboard"
echo "Partner Site: http://localhost:9000"
