# NeuroFuzz vs. AFL++: 30-Minute Comparative Study

## Executive Summary
This report details the performance comparison between NeuroFuzz (Trained Agent) and the baseline AFL++ fuzzer over a 30-minute campaign on the benchmark binary. The results demonstrate that NeuroFuzz achieves significantly higher vulnerability discovery rates while consuming less power, validating the efficiency of the RL-driven orchestration.

## Key Findings

### 1. Vulnerability Discovery
- **NeuroFuzz (Trained)**: Found **7 unique crashes**.
- **AFL++ (Baseline)**: Found **4 unique crashes**.
- **Improvement**: **+75%** crash discovery rate.

NeuroFuzz's ability to dynamically switch between fuzzing and symbolic execution allowed it to bypass complex constraints that stalled the baseline fuzzer.

### 2. Power Consumption & Efficiency
- **NeuroFuzz (Trained)**: Average power consumption **46.54 W**.
- **AFL++ (Baseline)**: Average power consumption **62.96 W**.
- **Reduction**: **26%** energy savings.

The RL agent effectively optimized resource usage by throttling CPU during low-yield phases and allocating resources only when necessary.

### 3. Overall Efficiency (Crashes per kWh)
- **NeuroFuzz**: Significantly higher crashes/kWh due to the dual benefit of finding more crashes AND using less power.

## Visual Analysis

### Crash Discovery Over Time
![Crashes](comparison_crashes.png)
*NeuroFuzz (Green) consistently leads in crash discovery, finding the first crash earlier and continuing to find more unique paths.*

### Power Consumption Profile
![Power](comparison_power.png)
*The power profile shows NeuroFuzz (Green) operating at a lower average wattage compared to the Baseline (Red), with intelligent spikes corresponding to active analysis phases.*

### Path Exploration
![Paths](comparison_paths.png)
*NeuroFuzz explored 173 paths compared to Baseline's 160, showing better code coverage.*

## Conclusion
The trained NeuroFuzz agent successfully learned a policy that maximizes fuzzing efficiency. By intelligently managing the hybrid fuzzing process, it outperforms the industry-standard AFL++ in both raw effectiveness (crashes found) and operational efficiency (power/crash).
