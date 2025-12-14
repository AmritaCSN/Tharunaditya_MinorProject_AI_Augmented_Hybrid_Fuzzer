# Symbolic Executor Component

## Overview
The **Symbolic Executor** (`src/analysis/symbolic_executor.py`) is the "heavy artillery" of NeuroFuzz. It uses **angr** to perform symbolic execution, solving complex path constraints that the fuzzer (AFL++) cannot bypass through random mutation.

It implements a **Driller-inspired concolic execution** strategy:
1.  Take a concrete input (seed) that reaches a specific path.
2.  Execute it symbolically, pre-constraining bytes to the concrete values.
3.  Identify branch points where the path could diverge.
4.  Negate the constraint at the branch point and use the **Z3 solver** to find a new input that takes the alternative path.

## Key Features

### 1. Multi-Strategy Exploration
The executor attempts three strategies in sequence to maximize success rates:

| Strategy | Method | Purpose |
| :--- | :--- | :--- |
| **1. Crash Directed** | `_crash_directed_exploration` | Finds inputs that lead to `errored` (crashes) or `unconstrained` (instruction pointer hijack) states. |
| **2. Targeted Address** | `_targeted_address_exploration` | Tries to reach a specific `BinaryTarget` address (e.g., a vulnerable function) while avoiding specified functions. |
| **3. Full Symbolic Fallback** | `_full_symbolic_fallback` | If concolic execution fails, attempts pure symbolic execution without pre-constraints (ignoring the seed). |

### 2. Selective Symbolization (Driller-Style)
To avoid state explosion, the executor doesn't make the entire input symbolic.
- **Pre-constraining**: It constrains symbolic bytes to match the concrete seed values.
- **Selective Bytes**: It can symbolize only a subset of bytes (critical bytes) while keeping the rest concrete.
- **Constraint Simplification**: Eagerly simplifies constraints to keep the solver fast.

### 3. Robust Input Extraction
Extracting the solved input from angr's state can be tricky. The executor uses a 4-stage fallback mechanism:
1.  `state.posix.dumps(0)`: Standard method for stdin.
2.  **Direct Variable Evaluation**: Searches for `stdin` or `stdin_symbolic` variables in the solver.
3.  **SimFile Load**: Loads data from the `state.posix.stdin` SimFile object.
4.  **File Descriptor Read**: Reads directly from file descriptor 0.

### 4. State Pruning
To prevent memory exhaustion and infinite loops:
- **Max States**: Limits the number of active states (default: 256).
- **Complexity Pruning**: Prioritizes states with simpler constraints.
- **Eager Simplification**: Simplifies constraints when they exceed a threshold (100).

## Technical Implementation

### Initialization
```python
executor = SymbolicExecutor(
    binary_path="binaries/vuln",
    max_depth=50,
    max_states=256,
    timeout_seconds=300,
    selective_symbolization=True
)
```
It automatically attempts to find a `_clean` (non-instrumented) version of the binary for faster symbolic execution, avoiding AFL++ instrumentation overhead.

### Monkey Patching
The module includes a critical monkey patch (`_patch_calling_convention_tuple_handling`) for `angr.calling_conventions.SimFunctionArgument`. This fixes a known issue where tuple return values from SimProcedures cause crashes during argument checking.

### Timeout Management
Uses Unix `signal.alarm` for hard timeouts to prevent the solver from hanging indefinitely (Z3 can sometimes take forever on complex constraints).

## Integration with Orchestrator
The `Orchestrator` calls `find_input_for_target` when:
1.  The RL agent selects the `SYMBOLIC_EXECUTION` action.
2.  Fuzzing coverage has plateaued (stuck).
3.  A high-priority target is identified but not reached.

## Configuration
Configured via `configs/*.yml` under `symbolic_execution`:
```yaml
symbolic_execution:
  enable: true
  max_states: 100
  max_depth: 50
  timeout_seconds: 300
```
