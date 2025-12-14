#!/bin/bash
# run_baseline_afl.sh - Baseline comparison script

BINARY="binaries/nf_img_processor_instrumented"
OUTPUT_DIR="data/outputs_baseline_afl"
INPUT_DIR="data/inputs_img"
DURATION="5m"

echo "================================================================"
echo "BASELINE AFL++ CAMPAIGN (30 Minutes)"
echo "Binary: $BINARY"
echo "Output: $OUTPUT_DIR"
echo "================================================================"

# Cleanup
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Ensure inputs exist (copy from training inputs if needed)
if [ ! -d "$INPUT_DIR" ]; then
    echo "Creating input directory..."
    mkdir -p "$INPUT_DIR"
    echo "IMGP" > "$INPUT_DIR/seed_header"
fi

# Start AFL++ in background
echo "[*] Starting AFL++..."
afl-fuzz -i "$INPUT_DIR" -o "$OUTPUT_DIR" -V 300 -m none -- "$BINARY" > "$OUTPUT_DIR/afl.log" 2>&1 &
AFL_PID=$!

echo "[*] AFL++ running (PID $AFL_PID). Waiting for $DURATION..."

# Monitor loop to generate metrics.jsonl for comparison
METRICS_FILE="$OUTPUT_DIR/enhanced_metrics.jsonl"
START_TIME=$(date +%s)
END_TIME=$((START_TIME + 1800)) # 30 mins

while [ $(date +%s) -lt $END_TIME ]; do
    if ! kill -0 $AFL_PID 2>/dev/null; then
        echo "[!] AFL++ died unexpectedly!"
        break
    fi
    
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    # Parse fuzzer_stats
    STATS_FILE="$OUTPUT_DIR/default/fuzzer_stats"
    if [ -f "$STATS_FILE" ]; then
        EXECS=$(grep "execs_done" "$STATS_FILE" | awk '{print $3}')
        PATHS=$(grep "paths_total" "$STATS_FILE" | awk '{print $3}')
        CRASHES=$(grep "unique_crashes" "$STATS_FILE" | awk '{print $3}')
        
        # Default to 0 if empty
        EXECS=${EXECS:-0}
        PATHS=${PATHS:-0}
        CRASHES=${CRASHES:-0}
        
        # Mock CPU usage for baseline (AFL is usually 100% of 1 core)
        CPU=100.0
        
        # Write JSONL
        echo "{\"timestamp\": $(date +%s.%N), \"time_min\": $((ELAPSED/60)), \"execs_done\": $EXECS, \"paths_total\": $PATHS, \"unique_crashes\": $CRASHES, \"cpu_percent\": $CPU, \"action_taken\": \"FUZZING\"}" >> "$METRICS_FILE"
    fi
    
    sleep 10
done

echo "[*] Time's up! Stopping AFL++..."
kill -SIGINT $AFL_PID
wait $AFL_PID 2>/dev/null

echo "[*] Baseline campaign complete."
