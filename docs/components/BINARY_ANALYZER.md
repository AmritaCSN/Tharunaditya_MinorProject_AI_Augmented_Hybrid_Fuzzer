# Binary Analyzer

## Overview
The `BinaryAnalyzer` is the first component in the NeuroFuzz pipeline. It performs static analysis on the target binary to understand its structure, control flow, and potential vulnerabilities. This analysis is crucial for the "Semantic Vulnerability Prioritization" feature, allowing the fuzzer to focus on dangerous code regions rather than exploring blindly.

## Key Responsibilities
1.  **CFG Construction**: Builds a Control Flow Graph (CFG) using `angr` to map all functions and their relationships.
2.  **Vulnerability Scoring**: Scans for known dangerous functions (e.g., `strcpy`, `system`) and assigns a "Vulnerability Score" to each function based on the dangerous calls it makes.
3.  **Target Extraction**: Produces a list of `BinaryTarget` objects, prioritized by risk, for the RL agent to consume.

## Class Reference

### `src.analysis.binary_analyzer.BinaryAnalyzer`

#### Initialization
```python
def __init__(self, max_functions: int = 100, timeout_per_function: int = 30)
```
- `max_functions`: Limit the analysis to the top N most interesting functions to save time.
- `timeout_per_function`: Maximum time (seconds) to spend analyzing a single function's complexity.

#### Main Method
```python
def analyze_binary(self, binary_path: str) -> AnalysisResult
```
- **Input**: Path to the compiled binary.
- **Output**: `AnalysisResult` object containing:
    - `targets`: List of `BinaryTarget` objects.
    - `high_priority_targets`: List of function names with score >= 7.0.
    - `metadata`: Architecture, entry point, etc.

## Vulnerability Scoring Logic

The analyzer maintains a dictionary of `DANGEROUS_FUNCTIONS` with associated risk scores. When analyzing a function, it checks if it calls any of these:

| Function | Score | Risk Category |
|----------|-------|---------------|
| `strcpy` | 10.0 | Buffer Overflow |
| `gets` | 10.0 | Buffer Overflow |
| `system` | 10.0 | Command Injection |
| `exec` | 10.0 | Command Injection |
| `strcat` | 9.0 | Buffer Overflow |
| `popen` | 9.0 | Command Injection |
| `sprintf` | 8.0 | Format String |
| `scanf` | 7.0 | Format String |
| `memcpy` | 4.0 | Memory Corruption |
| `malloc` | 2.0 | Heap Management |

### Custom Crash Patterns
The analyzer also prioritizes functions matching specific patterns often used in CTF challenges or test suites:
- `hard1_`, `hard2_` (Symbolic execution required)
- `easy1_`, `easy2_` (Fuzzing targets)
- `vuln`, `process_`, `dispatch_`, `handle_`, `parse_`, `secretcode`, `admin`

## Internal Logic

1.  **Load Binary**: Uses `angr.Project` to load the binary without auto-loading libraries (for speed).
2.  **Build CFG**: Calls `project.analyses.CFGFast()` to generate the Control Flow Graph.
3.  **Iterate Functions**: Loops through all functions found in the CFG.
4.  **Calculate Score**:
    - Base score: 1.0
    - For each call to a dangerous function: `score += dangerous_score`
    - For each call to a custom pattern: `score += 5.0`
    - Complexity bonus: `score += (cyclomatic_complexity * 0.1)`
5.  **Filter & Sort**: Removes system functions (CRT), sorts by score descending, and truncates to `max_functions`.

## Dependencies
- **angr**: The core binary analysis framework.
- **networkx**: Used internally by angr for graph algorithms.
