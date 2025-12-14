# Feedback Collector Component

## Overview
The **Feedback Collector** (`src/utils/feedback_collector.py`) is the "sensory organ" of NeuroFuzz. It continuously monitors the AFL++ fuzzer and system resources, aggregating data into a unified stream of `FuzzingSnapshot` events.

It provides the critical data needed for:
1.  **RL Observation**: Real-time state for the PPO agent.
2.  **Stuck Detection**: Determining when to trigger symbolic execution.
3.  **Post-Campaign Analysis**: Generating detailed reports and plots.

## Key Features

### 1. Unified Data Collection
It combines data from multiple sources into a single snapshot:
- **AFL++ Stats**: Reads `fuzzer_stats` (execs, paths, crashes, speed).
- **System Resources**: Uses `psutil` to track CPU and Memory usage.
- **Derived Metrics**: Calculates rates (crashes/hour) and estimates coverage.

### 2. Adaptive Stuck Detection
To decide when the fuzzer has plateaued, the collector implements two heuristics:

#### Time-Based (Simple)
`is_fuzzer_stuck(threshold=120s)`: Returns true if no new paths have been found in the last 120 seconds.

#### Execution-Based (Adaptive - Preferred)
`is_fuzzer_stuck_adaptive(input_size)`: Returns true if no new paths have been found for `input_size * 40` executions.
- **Why?** This scales with execution speed. A fast fuzzer (10k execs/sec) gets "stuck" faster than a slow one (100 execs/sec).
- **Sweet Spot**: The multiplier `40` was tuned to balance exploration vs. exploitation.

### 3. Seed Retrieval for Concolic Execution
When the fuzzer is stuck, the `SymbolicExecutor` needs a concrete input to start from.
`get_last_interesting_seed()`:
- Scans the AFL++ queue directory.
- Sorts files by modification time (newest first).
- Returns the content of the most recent "interesting" test case.

### 4. Historical Logging
Every snapshot is logged to `enhanced_metrics.jsonl` in the campaign directory. This allows for:
- **Replay**: Reconstructing the campaign timeline.
- **Plotting**: Generating graphs of coverage growth, speed, and resource usage.
- **Trend Analysis**: Calculating growth rates over sliding windows.

## Technical Implementation

### Data Structure
```python
@dataclass
class FuzzingSnapshot:
    timestamp: float
    execs_done: int
    paths_total: int
    crashes_total: int
    cpu_percent: float
    memory_percent: float
    action_taken: str  # "FUZZING" or "SYMBOLIC_EXECUTION"
    # ... and more
```

### Usage in Orchestrator
```python
# Get current stats for RL observation
stats = feedback_collector.get_stats(action_taken="FUZZING")

# Check if stuck
is_stuck, execs_since, threshold = feedback_collector.get_stuck_metrics()

# Get summary for report
summary = feedback_collector.get_summary()
```

## Integration
- **Input**: Reads `data/outputs/default/fuzzer_stats` and system metrics.
- **Output**: Writes to `data/campaigns/<name>/enhanced_metrics.jsonl`.
- **Consumer**: Used by `NeuroFuzzEnv` (for rewards/observations) and `NeuroFuzzEvaluator` (for reports).
