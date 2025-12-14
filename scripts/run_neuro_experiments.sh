#!/usr/bin/env bash
set -euo pipefail

# Orchestrate: build target, prepare seeds, run 1hr NeuroFuzz train, 1hr NeuroFuzz run, 1hr AFL baseline
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

echo "1) Build instrumented netstat-like target"
bash binaries/build_netstat.sh

echo "2) Ensure seed directory exists (minimal seed)"
mkdir -p data/inputs_neuro
if [[ ! -s data/inputs_neuro/seed_00000 ]]; then
  # Create a more realistic-looking seed for a netstat-like tool
  echo "NETSTAT,127.0.0.1,127.0.0.1,64,OK,0,NETSTAT_PAYLOAD" > data/inputs_neuro/seed_00000
fi

echo "3) Start NeuroFuzz training for 60 minutes"
python3 neurofuzz.py --config configs/neuro_train_1hr.yml 2>&1 | tee /tmp/neuro_train_1hr.log &
TRAIN_PID=$!
echo "Training started (PID=$TRAIN_PID). Waiting 60 minutes..."
sleep 3600
echo "Stopping training (PID=$TRAIN_PID)"
kill -TERM "$TRAIN_PID" || true
wait "$TRAIN_PID" || true

echo "4) Run NeuroFuzz with trained model for 60 minutes"
python3 neurofuzz.py --config configs/neuro_run_1hr.yml 2>&1 | tee /tmp/neuro_run_1hr.log &
RUN_PID=$!
sleep 3600
echo "Stopping run (PID=$RUN_PID)"
kill -TERM "$RUN_PID" || true
wait "$RUN_PID" || true

echo "5) Run AFL++ baseline for 60 minutes"
# Use run_baseline_afl.sh if present, otherwise invoke afl-fuzz directly
if [[ -x run_baseline_afl.sh ]]; then
  bash run_baseline_afl.sh --config configs/neuro_baseline_afl_1hr.yml 2>&1 | tee /tmp/neuro_baseline_1hr.log
else
  echo "run_baseline_afl.sh not found or executable; running afl-fuzz directly"
  mkdir -p data/outputs_neuro_baseline
  afl-fuzz -i data/inputs_neuro -o data/outputs_neuro_baseline -m none -t 1000+ -D 3600 ./binaries/neuro_target_instrumented
fi

echo "6) Evaluation: run evaluator on each campaign output (if orchestrator didn't)"
python3 neurofuzz.py --config configs/neuro_baseline_afl_1hr.yml --mode evaluate || true

echo "Experiments finished. Logs: /tmp/neuro_train_1hr.log, /tmp/neuro_run_1hr.log, /tmp/neuro_baseline_1hr.log"
