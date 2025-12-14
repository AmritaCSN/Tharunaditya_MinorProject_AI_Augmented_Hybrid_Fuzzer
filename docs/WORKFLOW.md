# NeuroFuzz Execution Workflow

This document describes the step-by-step lifecycle of a NeuroFuzz campaign, from the initial command to the final report.

## 1. Initialization Phase

**Command**: `python neurofuzz.py --config configs/train_demo.yml`

1.  **Config Loading**: The YAML configuration is parsed to determine the mode (`train` vs `run`), target binary, and resource limits.
2.  **System Checks**: Verifies that `afl-fuzz` is installed, the binary exists, and the output directory is clean.
3.  **Binary Analysis**:
    - The `BinaryAnalyzer` loads the target binary using `angr`.
    - It constructs a Control Flow Graph (CFG).
    - It identifies "Dangerous Functions" (e.g., `strcpy`) and calculates vulnerability scores.
    - **Output**: `data/campaigns/<name>/binary_config.json`
4.  **Seed Generation**:
    - If `data/inputs` is empty, `AISeedGenerator` creates ~100 diverse seeds (text, binary, format strings).

## 2. The Training Loop (RL Episode)

The system enters the main loop, controlled by the PPO Agent.

### Step A: Observation
The `NeuroFuzzEnv` queries the `FeedbackCollector` for the current state:
- **Execs/sec**: Is AFL running fast?
- **Bitmap Coverage**: How much code have we seen?
- **Last Path Time**: How long since we found something new?

### Step B: Action Selection
The PPO Agent (trained model) observes the state and selects an action:
- **Action 0: FUZZING** (Most common)
- **Action 1: SYMBOLIC_EXECUTION** (When stuck)

### Step C: Execution

#### Scenario 1: Action = FUZZING
1.  **Check AFL**: If AFL++ is not running, start it.
2.  **Monitor**: Let AFL++ run for `t` seconds (defined in config).
3.  **Collect Stats**: Read `fuzzer_stats` to update metrics.

#### Scenario 2: Action = SYMBOLIC_EXECUTION
1.  **Target Selection**: Pick the highest priority target from `binary_config.json` that hasn't been solved yet.
2.  **Strategy Selection**:
    - **Attempt 1 (Smart Concolic)**: Use a seed from the AFL queue to constrain the solver. This is fast but can fail on complex checks.
    - **Attempt 2 (Full Symbolic)**: If Attempt 1 fails, relax all constraints. This is slower but can solve "Magic Numbers" (e.g., `0xDEADBEEF`).
3.  **Result Handling**:
    - If a solution is found, write it to `data/outputs/queue/id:symex...`.
    - AFL++ automatically picks up this new seed and explores the new path.

### Step D: Reward Calculation
The environment calculates the reward for the step:
- **Base**: `-0.1` (Encourages speed).
- **Bonus**: `+1.0` if a crash was found.
- **Bonus**: `+0.5` if a new path was found.
- **Penalty**: `-0.5` if no new paths were found (Stagnation).

## 3. Termination & Reporting

The campaign ends when:
- The time limit is reached (e.g., 30 minutes).
- The step limit is reached.
- The user interrupts (Ctrl+C).

**Post-Processing**:
1.  **Model Saving**: The trained PPO model is saved to `data/models/`.
2.  **Evaluation**: The `Evaluator` generates plots:
    - `crashes_over_time.png`
    - `coverage_over_time.png`
    - `action_distribution.png`
3.  **Report**: A JSON summary is saved to `data/campaigns/<name>/evaluation/report.json`.

## 4. Crash Verification

To verify findings:
1.  Locate crashes in `data/outputs/default/crashes/`.
2.  Replay them against the binary:
    ```bash
    cat data/outputs/default/crashes/id:000000... | ./binaries/target
    ```
