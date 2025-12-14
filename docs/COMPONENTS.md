# NeuroFuzz Component Reference

This document details the internal modules of NeuroFuzz, their responsibilities, and key implementation details.

For detailed technical specifications of each component, please refer to the linked documents.

## 1. Core Layer (`src/core/`)

### `NeuroFuzzOrchestrator`
[📄 Detailed Documentation](components/ORCHESTRATOR.md)
- **Role**: The central controller. It initializes all subsystems, manages the main event loop, and executes the actions dictated by the RL agent.
- **Key Responsibilities**:
  - Managing the AFL++ subprocess (start, stop, monitor).
  - Triggering Symbolic Execution tasks.
  - Collecting metrics via `FeedbackCollector`.
  - Handling the "Stuck" state (detecting when fuzzing yields no new paths).
- **Location**: `src/core/orchestrator.py`

### `Interfaces`
- **Role**: Defines the abstract base classes (ABCs) to ensure modularity and testability.
- **Key Interfaces**: `IBinaryAnalyzer`, `IFuzzer`, `ISymbolicExecutor`, `IRLEnvironment`.
- **Location**: `src/core/interfaces.py`

---

## 2. Analysis Layer (`src/analysis/`)

### `BinaryAnalyzer`
[📄 Detailed Documentation](components/BINARY_ANALYZER.md)
- **Role**: Performs static analysis on the target binary to understand its structure and identify interesting targets.
- **Technology**: `angr` (CFG recovery).
- **Key Features**:
  - **Vulnerability Scoring**: Scans for dangerous functions (`strcpy`, `system`, `gets`) and assigns scores (e.g., 10.0 for `strcpy`).
  - **CFG Construction**: Builds a Control Flow Graph to map function relationships.
- **Location**: `src/analysis/binary_analyzer.py`

### `SymbolicExecutor`
[📄 Detailed Documentation](components/SYMBOLIC_EXECUTOR.md)
- **Role**: The "Solver". It uses symbolic execution to generate inputs that reach specific targets or satisfy complex constraints.
- **Technology**: `angr`, `claripy`, `Z3`.
- **Strategies**:
  1.  **Crash Exploration**: Looks for states that trigger memory errors.
  2.  **Targeted Exploration**: Tries to reach a specific address (e.g., a vulnerable function).
  3.  **Full Symbolic Fallback**: If constrained execution fails, it relaxes constraints to find *any* valid path to the target.
- **Location**: `src/analysis/symbolic_executor.py`

### `TargetConfigGenerator`
[📄 Detailed Documentation](components/TARGET_CONFIG.md)
- **Role**: Processes the raw analysis results into a prioritized list of targets for the RL agent.
- **Output**: `binary_config.json`
- **Location**: `src/analysis/target_config.py`

---

## 3. Fuzzing Layer (`src/fuzzing/`)

### `AFLFuzzer`
[📄 Detailed Documentation](components/AFL_FUZZER.md)
- **Role**: A wrapper around the AFL++ binary.
- **Key Responsibilities**:
  - Launching `afl-fuzz` with correct parameters.
  - Managing input/output directories.
  - Parsing `fuzzer_stats` in real-time.
  - Cleaning up processes on exit.
- **Configuration**: Supports standard AFL++ env vars (`AFL_SKIP_CPUFREQ`, etc.).
- **Location**: `src/fuzzing/afl_fuzzer.py`

---

## 4. Reinforcement Learning Layer (`src/rl/`)

### `NeuroFuzzEnv`
[📄 Detailed Documentation](components/RL_ENVIRONMENT.md)
- **Role**: A Gymnasium-compatible environment that exposes the fuzzing process to the RL agent.
- **Observation Space**: 12-dimensional vector including:
  - Execution Speed
  - Coverage Density
  - Stability
  - Time since last path
  - Crash count
  - SymEx ROI
- **Action Space**: Discrete(2):
  0. `FUZZING` (Continue AFL)
  1. `SYMBOLIC_EXECUTION` (Trigger Solver)
- **Reward Function**:
  - `+10.0` for finding a Crash.
  - `+0.5` for finding a New Path.
  - `+20.0` for Unsticking the Fuzzer.
  - `-5.0` for triggering SymEx when not stuck.
- **Location**: `src/rl/environment.py`

---

## 5. Utilities (`src/utils/`)

### `FeedbackCollector`
[📄 Detailed Documentation](components/FEEDBACK_COLLECTOR.md)
- **Role**: Aggregates data from AFL++ stats files and system metrics.
- **Location**: `src/utils/feedback_collector.py`

### `AISeedGenerator`
[📄 Detailed Documentation](components/SEED_GENERATOR.md)
- **Role**: Generates initial seed inputs if none are provided. Creates a mix of random ASCII, binary, and format string patterns.
- **Location**: `src/utils/seed_generator.py`

### `PowerTracker`
- **Role**: Estimates energy consumption of the fuzzing campaign (Joules/Watts).
- **Location**: `src/utils/energy_estimator.py`

