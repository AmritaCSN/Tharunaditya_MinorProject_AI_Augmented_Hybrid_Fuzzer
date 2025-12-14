#!/bin/bash
# run_comparative_study.sh
# Automates the full 3-hour experiment: Training -> Run -> Baseline -> Comparison

echo "================================================================"
echo "NEUROFUZZ COMPARATIVE STUDY (3 HOURS)"
echo "================================================================"

# 1. Training Phase (60 mins)
echo ""
echo "[PHASE 1/3] Training NeuroFuzz Agent (60 mins)..."
python neurofuzz.py --config configs/train_60min.yml

# 2. Run Phase (60 mins)
echo ""
echo "[PHASE 2/3] Running Trained Agent (60 mins)..."
# PARANOID CLEANUP: Ensure no data leakage from training
rm -rf data/outputs
rm -rf data/inputs_cgc_cadet_00001
python neurofuzz.py --config configs/run_60min.yml

# 3. Baseline Phase (60 mins)
echo ""
echo "[PHASE 3/3] Running Baseline AFL++ (60 mins)..."
./scripts/run_baseline_60min.sh

# 4. Generate Comparison Plots
echo ""
echo "[PHASE 4/4] Generating Comparison Plots..."
python scripts/generate_comparison_plots.py \
    "data/campaigns/train_60min" \
    "data/campaigns/run_60min" \
    "data/outputs_baseline_60min" \
    "data/comparison_results"

echo ""
echo "================================================================"
echo "STUDY COMPLETE"
echo "Results available in data/comparison_results/"
echo "================================================================"
