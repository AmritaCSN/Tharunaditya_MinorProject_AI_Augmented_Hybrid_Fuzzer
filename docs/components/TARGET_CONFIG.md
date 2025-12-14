# Target Configuration Generator

## Overview
The `TargetConfigGenerator` acts as a bridge between the raw static analysis (`BinaryAnalyzer`) and the execution engine (`NeuroFuzzOrchestrator`). It takes the raw list of functions and enriches them with semantic tags, resource limits, and specific "avoid" patterns to create a robust fuzzing plan.

## Key Responsibilities
1.  **Filtering**: Removes C Runtime (CRT) functions and other noise that shouldn't be fuzzed.
2.  **Enrichment**: Adds semantic tags (e.g., `buffer_overflow`, `format_string`) based on the dangerous functions identified.
3.  **Configuration**: Sets timeouts and memory limits for symbolic execution based on target complexity.
4.  **Serialization**: Saves the final plan to `binary_config.json`.

## Class Reference

### `src.analysis.target_config.TargetConfigGenerator`

#### Initialization
```python
def __init__(self)
```
Initializes the generator with default resource limits and skip patterns.

#### Main Method
```python
def generate(self, analysis_result: AnalysisResult, output_path: str) -> BinaryConfig
```
- **Input**: The `AnalysisResult` from the `BinaryAnalyzer`.
- **Output**: A `BinaryConfig` object (also saved to `output_path`).

## Filtering Logic

### CRT Skip Patterns
The generator explicitly ignores functions matching these patterns to avoid wasting resources on standard library initialization code:
- `__tmainCRTStartup`, `_start`, `__libc_start_main`
- `__mingw_`, `__security_`, `__SEH_`
- `atexit`, `pre_c_init`

### Avoid Patterns
For symbolic execution, it identifies "Error Handler" functions that should be avoided (treated as dead ends) to keep the solver focused on success paths:
- `exit`, `abort`, `_exit`
- `error`, `fatal`, `panic`
- `__stack_chk_fail` (Stack canary failure)

## Semantic Tagging

The generator maps dangerous functions to vulnerability classes:

| Function | Tags |
|----------|------|
| `strcpy`, `strcat` | `buffer_overflow`, `unsafe_string` |
| `gets` | `buffer_overflow`, `unsafe_input` |
| `sprintf`, `vsprintf` | `buffer_overflow`, `format_string` |
| `scanf`, `fscanf` | `format_string`, `unsafe_input` |
| `malloc`, `free` | `heap_corruption`, `memory_management` |
| `system`, `exec` | `command_injection`, `code_execution` |

## Output Format (`binary_config.json`)

```json
{
  "binary_path": "binaries/vuln",
  "targets": [
    {
      "name": "vulnerable_function",
      "address": "0x401234",
      "priority": 15.0,
      "target_type": "function",
      "avoid_addresses": ["0x401999"],
      "timeout": 300,
      "semantic_tags": ["buffer_overflow"],
      "risk_breakdown": {"strcpy": 10.0}
    }
  ]
}
```
