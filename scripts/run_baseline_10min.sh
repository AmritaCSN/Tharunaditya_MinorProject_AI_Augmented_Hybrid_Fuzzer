#!/bin/bash
# run_baseline_10min.sh - Baseline comparison script (10 Minutes)

BINARY="binaries/cgc_cadet_00001_instrumented"
OUTPUT_DIR="data/outputs_baseline_10min"
INPUT_DIR="data/inputs_cgc_cadet_00001"
DURATION_SEC=600

echo "================================================================"
echo "BASELINE AFL++ CAMPAIGN (10 Minutes)"
echo "Binary: $BINARY"
echo "Output: $OUTPUT_DIR"
echo "================================================================"

# Cleanup
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Ensure inputs exist
if [ ! -d "$INPUT_DIR" ]; then
    echo "Error: Input directory $INPUT_DIR does not exist."
    exit 1
fi

# Start AFL++ in background
echo "[*] Starting AFL++..."
afl-fuzz -i "$INPUT_DIR" -o "$OUTPUT_DIR" -V $DURATION_SEC -m none -- "$BINARY" > "$OUTPUT_DIR/afl.log" 2>&1 &
AFL_PID=$!

echo "[*] AFL++ running (PID $AFL_PID). Waiting for 10 minutes..."

# Monitor loop to generate metrics.jsonl for comparison
METRICS_FILE="$OUTPUT_DIR/enhanced_metrics.jsonl"
START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION_SEC))

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
        PATHS=$(grep "corpus_count" "$STATS_FILE" | awk '{print $3}')
        CRASHES=$(grep "saved_crashes" "$STATS_FILE" | awk '{print $3}')
        SPEED=$(grep "execs_per_sec" "$STATS_FILE" | awk '{print $3}')
        CVG=$(grep "bitmap_cvg" "$STATS_FILE" | awk '{print $3}' | sed 's/%//')
        
        # Default to 0 if empty
        EXECS=${EXECS:-0}
        PATHS=${PATHS:-0}
        CRASHES=${CRASHES:-0}
        SPEED=${SPEED:-0}
        CVG=${CVG:-0}
        
        # Get System-wide CPU Usage (fair comparison with NeuroFuzz's psutil)
        # top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}'
        # Alternative using mpstat if available, or /proc/stat
        
        # Simple /proc/stat calculation for system CPU
        read cpu a b c idle rest < /proc/stat
        prev_idle=$idle
        prev_total=$((a+b+c+idle))
        sleep 0.1
        read cpu a b c idle rest < /proc/stat
        total=$((a+b+c+idle))
        diff_idle=$((idle-prev_idle))
        diff_total=$((total-prev_total))
        CPU_USAGE=$((100 * (diff_total - diff_idle) / diff_total))
        
        # Memory is harder to match exactly, but we'll stick to process mem for now or use free
        # Let's use process mem for consistency with what we can easily measure
        MEM_USAGE=$(ps -p $AFL_PID -o %mem --no-headers 2>/dev/null)
        MEM_USAGE=${MEM_USAGE:-0.0}
        
        # Estimate Power (Simple model: Base 45W + (CPU% * 0.7))
        # This matches the logic in NeuroFuzz's PowerTracker for fair comparison
        # Use python for float math since bc might be missing
        POWER_WATTS=$(python3 -c "print(45.0 + ($CPU_USAGE * 0.7))")
        
        # Append to JSONL
        echo "{\"timestamp\": $CURRENT_TIME, \"session_runtime\": $ELAPSED, \"execs_done\": $EXECS, \"paths_total\": $PATHS, \"crashes_total\": $CRASHES, \"execs_per_sec\": $SPEED, \"coverage_estimate\": $CVG, \"cpu_percent\": $CPU_USAGE, \"memory_percent\": $MEM_USAGE, \"estimated_watts\": $POWER_WATTS, \"action\": \"BASELINE\"}" >> "$METRICS_FILE"
    fi
    
    sleep 15
done

echo "[*] Time limit reached. Stopping AFL++..."
kill -SIGTERM $AFL_PID 2>/dev/null
wait $AFL_PID 2>/dev/null

echo "[*] Baseline campaign complete."
