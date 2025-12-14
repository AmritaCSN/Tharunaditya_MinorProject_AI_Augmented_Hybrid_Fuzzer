#!/bin/bash
# run_comparative_study_10min.sh
# Automates the 30-minute experiment: Training (10m) -> Run (10m) -> Baseline (10m) -> Comparison

echo "================================================================"
echo "NEUROFUZZ COMPARATIVE STUDY (30 MINUTES)"
echo "================================================================"

# 1. Training Phase (10 mins)
echo ""
echo "[PHASE 1/3] Training NeuroFuzz Agent (10 mins)..."
python neurofuzz.py --config configs/train_10min.yml

# 2. Run Phase (10 mins)
echo ""
echo "[PHASE 2/3] Running Trained Agent (10 mins)..."
# PARANOID CLEANUP: Ensure no data leakage from training
rm -rf data/outputs
rm -rf data/inputs_cgc_cadet_00001
python neurofuzz.py --config configs/run_10min.yml

# 3. Baseline Phase (10 mins)
echo ""
echo "[PHASE 3/3] Running Baseline AFL++ (10 mins)..."
./scripts/run_baseline_10min.sh

# 4. Generate Comparison Plots
echo ""
echo "[PHASE 4/4] Generating Comparison Plots..."
python scripts/generate_comparison_plots.py \
    "data/campaigns/train_10min" \
    "data/campaigns/run_10min" \
    "data/outputs_baseline_10min" \
    "data/comparison_results_10min"

echo ""
echo "================================================================"
echo "STUDY COMPLETE"
echo "Results available in data/comparison_results_10min/"
echo "================================================================"
