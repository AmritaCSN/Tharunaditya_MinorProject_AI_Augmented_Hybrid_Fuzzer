# Research Goals & Academic Alignment

NeuroFuzz is designed to address specific challenges in the field of automated vulnerability discovery. This document outlines how the project's features align with academic research goals.

## 1. Resource Efficiency in Hybrid Fuzzing

**Problem**: Traditional hybrid fuzzers (like Driller) often waste resources by launching symbolic execution too frequently or on unreachable targets. Symbolic execution is computationally expensive (exponential complexity).

**NeuroFuzz Solution**:
- **RL-Driven Scheduling**: The PPO agent learns *when* to use symbolic execution. It avoids triggering the solver if the fuzzer is making good progress on its own (high "Execs/sec" and "New Paths").
- **Metric**: We measure **Crashes per CPU-Hour** and **Energy Consumption (Joules)** to demonstrate efficiency gains over baseline AFL++.

## 2. Intelligent Resource Orchestration

**Problem**: Fuzzers typically run with static resource limits. They don't adapt to the changing needs of the campaign (e.g., needing more memory for deep recursion).

**NeuroFuzz Solution**:
- **Dynamic Action Space**: The RL agent has actions to `REALLOCATE_CORE` and `REALLOCATE_MEMORY` (framework in place).
- **Observation Space**: The agent observes system load and stability, allowing it to learn policies that balance throughput with stability.

## 3. Semantic Vulnerability Prioritization

**Problem**: Coverage-guided fuzzers (AFL) treat all code paths equally. They might spend hours exploring a benign print function while ignoring a dangerous memory copy routine.

**NeuroFuzz Solution**:
- **Vulnerability Scoring**: We use static analysis (`BinaryAnalyzer`) to identify and score functions based on their potential for harm (e.g., `strcpy` = High Risk).
- **Directed Symbolic Execution**: When the agent triggers symbolic execution, it doesn't just pick a random frontier; it targets the highest-priority reachable function.

## 4. Adaptive Fallback Strategies

**Problem**: Symbolic execution engines often fail due to "Path Explosion" or over-constrained states, causing hybrid fuzzers to give up on hard targets.

**NeuroFuzz Solution**:
- **Multi-Strategy Solver**: We implement a tiered approach:
    1.  **Smart Concolic**: Fast, seed-constrained.
    2.  **Full Symbolic**: Slow, unconstrained (Fallback).
- **Research Value**: This demonstrates that a "one-size-fits-all" solver strategy is insufficient for diverse binaries.

## Evaluation Metrics

To validate these goals, NeuroFuzz collects:
1.  **Time-to-First-Crash**: Speed of discovery.
2.  **Unique Crashes**: Depth of discovery.
3.  **Branch Coverage**: Breadth of exploration.
4.  **Energy Efficiency**: Power consumed per bug found.
5.  **Action Distribution**: How the agent's strategy evolves over time (e.g., does it learn to stop using SymEx when it's ineffective?).
