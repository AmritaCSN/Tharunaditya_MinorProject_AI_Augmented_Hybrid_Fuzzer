# AI Seed Generator Component

## Overview
The **AI Seed Generator** (`src/utils/seed_generator.py`) is responsible for creating the initial corpus of inputs for the fuzzing campaign. Instead of starting with empty or random files, it uses intelligent strategies to generate seeds that are likely to trigger edge cases in the target binary.

It works in tandem with the `TargetConfigGenerator`, using "hints" derived from static analysis (e.g., "this binary uses `printf`, so generate format strings") to tailor the corpus.

## Key Features

### 1. Diverse Generation Strategies
The generator employs 8 distinct strategies to cover different classes of vulnerabilities:

| Strategy | Description | Target Vulnerability |
| :--- | :--- | :--- |
| `random_ascii` | Random alphanumeric strings. | General logic errors. |
| `random_binary` | Random byte sequences. | Binary parsers, integer overflows. |
| `format_strings` | Strings like `%x%x%n%s`. | Format string bugs (`printf`). |
| `buffer_boundaries` | Strings of length $2^n \pm 1$ (e.g., 255, 256, 257). | Buffer overflows, off-by-one errors. |
| `special_chars` | Null bytes, newlines, shell chars (`|`, `;`, `$`). | Command injection, parser errors. |
| `repeated_patterns` | Long sequences of repeated bytes (`AAAA...`). | Buffer overflows. |
| `gradient_lengths` | Strings of increasing length. | Length checks. |
| `mixed_content` | Combination of the above. | Complex parsing logic. |

### 2. Hint-Based Generation
Static analysis can provide hints about what the binary expects. The generator adapts its output based on these hints:

- **`format_specifiers`**: Increases the ratio of format string payloads.
- **`long_strings`**: Generates massive buffers (4KB+) to test `strcpy`/`strcat`.
- **`boundary_values`**: Focuses on integer limits and buffer edges.
- **`shell_metacharacters`**: Injects characters like `; /bin/sh` if `system()` calls are detected.

### 3. Deduplication
It maintains a set of `generated_patterns` to ensure that every seed in the corpus is unique, maximizing the efficiency of the initial fuzzing phase.

## Technical Implementation

### Initialization
```python
generator = AISeedGenerator(config)
```
Configuration is loaded from `config.yml` under `seed_generation`:
```yaml
seed_generation:
  num_seeds: 100
  max_size: 4096
  strategies: ["random_ascii", "format_strings", ...]
```

### Generation Process
```python
summary = generator.generate_seeds(
    output_dir="data/inputs",
    hints=["format_specifiers", "long_strings"]
)
```
1.  **Strategy Distribution**: Divides the total `num_seeds` evenly among the active strategies.
2.  **Hint Augmentation**: Generates additional seeds specifically targeting the provided hints.
3.  **File Creation**: Writes each seed to `seed_<id>_<strategy>.txt`.
4.  **Summary**: Returns a `SeedGenerationSummary` object with statistics.

### Output
The generator produces a `seed_summary.json` file in the campaign directory, detailing:
- Total seeds generated.
- Breakdown by strategy.
- Total size in bytes.
- Unique patterns count.

## Integration
- **Called by**: `Orchestrator` during the initialization phase (Step 3/8).
- **Input**: `BinaryConfig` hints from the `TargetConfigGenerator`.
- **Output**: Populates the `data/inputs/` directory, which is then passed to `AFLFuzzer`.
