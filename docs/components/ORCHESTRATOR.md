# Orchestrator Component

## Overview
The **Orchestrator** (`src/core/orchestrator.py`) is the central nervous system of NeuroFuzz. It initializes, coordinates, and manages the lifecycle of all other components. It bridges the gap between the high-level Reinforcement Learning decision-making and the low-level execution of fuzzing and symbolic analysis tools.

## Key Responsibilities

### 1. System Initialization
- **Auto-Compilation**: Detects if the target is a C source file and automatically compiles it with AFL++ instrumentation (`afl-clang-fast`).
- **Component Setup**: Initializes the Analyzer, Fuzzer, Symbolic Executor, RL Environment, and PPO Agent.
- **Directory Management**: Creates the campaign directory structure for logs, models, and crash artifacts.

### 2. Campaign Management
The orchestrator supports three modes of operation:
- **Train**: Trains the PPO agent from scratch to learn an optimal policy.
- **Run**: Executes a fuzzing campaign using a pre-trained model.
- **Analyze**: Performs static analysis on the binary without running the fuzzer.

### 3. Execution Logic

#### Fuzzing Step
```python
orchestrator.execute_fuzzing_step()
```
- Runs AFL++ for a specific time budget (default: 30s).
- **Adaptive Scheduling**: Checks `ResourceController` to throttle execution if CPU/RAM usage is critical.
- **Feedback Collection**: Gathers real-time stats from AFL++ to update the RL environment.

#### Symbolic Execution Step
```python
orchestrator.execute_symbolic_execution(target)
```
- **Stuck Detection**: Checks if the fuzzer has plateaued (no new paths for N executions).
- **Priority Override**: Allows symbolic execution even if not stuck, *if* the target is high-priority (Semantic Vulnerability Prioritization).
- **Concolic Execution**:
    1.  Retrieves the last interesting seed from the AFL++ queue.
    2.  Spawns a separate process for the `SymbolicExecutor` (to isolate crashes/hangs).
    3.  If a solution is found, saves it as a new seed in the AFL++ queue (`id:...,src:symex,op:unstuck`).

### 4. Training & Monitoring
- **PPO Integration**: Uses Stable Baselines 3 to train the agent.
- **Custom Callbacks**:
    - `DetailedProgressCallback`: Logs every step to the console with emojis and metrics.
    - `TimeLimitCallback`: Enforces the training duration.
- **Policy Health**: Validates that the trained policy isn't degenerate (e.g., always choosing the same action) before saving.

### 5. Reporting
At the end of a campaign, the orchestrator:
- **Extracts Crashes**: Copies unique crash files from AFL++ to the campaign folder.
- **Generates Reports**: Calls `NeuroFuzzEvaluator` to create detailed JSON/Markdown reports.
- **Energy Tracking**: Saves power consumption metrics via `PowerTracker`.

## Technical Implementation

### Initialization
```python
orchestrator = NeuroFuzzOrchestrator()
orchestrator.initialize(config)
```

### Running a Campaign
```python
results = orchestrator.run_campaign(mode="train")
```

### Seed Injection
When symbolic execution finds a new path, the orchestrator injects the solution back into AFL++:
```python
_save_seed_to_afl_queue(solution, target_name, timestamp)
```
It uses a specific filename format so AFL++ picks it up immediately and the system can track attribution later.

## Configuration
The orchestrator is configured via the main `config.yml` file, which it passes down to sub-components. It overrides defaults based on the specific campaign configuration (e.g., `train_30min.yml`).
