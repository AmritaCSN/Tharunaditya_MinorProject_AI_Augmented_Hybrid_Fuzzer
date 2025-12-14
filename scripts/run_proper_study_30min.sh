#!/bin/bash
# run_proper_study_30min.sh
# Automates the full 30-minute PROPER experiment: Training -> Run -> Baseline -> Comparison

echo "================================================================"
echo "NEUROFUZZ PROPER COMPARATIVE STUDY (30 MINS)"
echo "================================================================"

# Activate virtual environment
source .venv/bin/activate

# 1. Training Phase (30 mins)
echo ""
echo "[PHASE 1/3] Training NeuroFuzz Agent (30 mins)..."
python neurofuzz.py --config configs/train_30min_proper.yml

# 2. Run Phase (30 mins)
echo ""
echo "[PHASE 2/3] Running Trained Agent (30 mins)..."
# Note: We do NOT delete inputs_proper here because we want to use the same initial seeds
# But NeuroFuzz with force_clean=true in config will regenerate them anyway, which is fine (same seed generator)
python neurofuzz.py --config configs/run_30min_proper.yml

# 3. Baseline Phase (30 mins)
echo ""
echo "[PHASE 3/3] Running Baseline AFL++ (30 mins)..."
chmod +x scripts/run_baseline_30min_proper.sh
./scripts/run_baseline_30min_proper.sh

# 4. Generate Comparison Plots
echo ""
echo "[PHASE 4/4] Generating Comparison Plots..."
python scripts/generate_comparison_plots.py \
    "data/campaigns/train_30min_proper" \
    "data/campaigns/run_30min_proper" \
    "data/outputs_baseline_proper" \
    "data/comparison_results_proper"

echo ""
echo "================================================================"
echo "PROPER STUDY COMPLETE"
echo "Results available in data/comparison_results_proper/"
echo "================================================================"
