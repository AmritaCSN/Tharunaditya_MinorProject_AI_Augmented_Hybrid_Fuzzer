import pandas as pd
from pathlib import Path

def load_afl_plot_data(plot_data_path, label):
    data = []
    if not plot_data_path.exists():
        print(f"Warning: {plot_data_path} not found")
        return pd.DataFrame()
    
    try:
        print(f"Reading {plot_data_path}...")
        # Read CSV
        df = pd.read_csv(plot_data_path, skipinitialspace=True)
        
        print("Original columns:", df.columns.tolist())
        
        # Clean up column names (remove # and spaces)
        df.columns = df.columns.str.strip().str.replace('# ', '').str.replace('#', '')
        
        print("Cleaned columns:", df.columns.tolist())
        
        if 'relative_time' not in df.columns:
            print("ERROR: 'relative_time' column not found!")
            return pd.DataFrame()

        for _, row in df.iterrows():
            try:
                # Parse coverage percentage (e.g., "65.00%")
                cov_str = str(row['map_size']).replace('%', '')
                coverage = float(cov_str)
            except:
                coverage = 0.0
                
            data.append({
                'Time (min)': row['relative_time'] / 60.0,
                'Crashes': row['saved_crashes'],
                'Paths': row['corpus_count'],
                'Coverage (%)': coverage,
                'Exec Speed': row['execs_per_sec'],
                'Power (W)': 0, # Baseline doesn't track power
                'CPU (%)': 0,   # Baseline doesn't track CPU
                'Run': label
            })
            
        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error parsing AFL plot_data: {e}")
        import traceback
        traceback.print_exc()
        return pd.DataFrame()

import json

def load_metrics(metrics_path, label):
    data = []
    if not metrics_path.exists():
        print(f"Warning: {metrics_path} not found")
        return pd.DataFrame()
    
    with open(metrics_path, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    entry = json.loads(line)
                    data.append({
                        'Time (min)': entry.get('session_runtime', 0) / 60.0,
                        'Crashes': entry.get('crashes_total', 0),
                        'Paths': entry.get('paths_total', 0),
                        'Coverage (%)': float(str(entry.get('coverage_estimate', 0)).replace('%', '')),
                        'Exec Speed': entry.get('execs_per_sec', 0),
                        'Power (W)': entry.get('estimated_watts', 0),
                        'CPU (%)': entry.get('cpu_percent', 0),
                        'Run': label
                    })
                except Exception as e:
                    continue
    return pd.DataFrame(data)

path = Path("data/outputs_baseline_proper/default/plot_data")
df_base = load_afl_plot_data(path, "AFL++ (Baseline)")
print(f"Baseline: {len(df_base)} rows")

train_path = Path("data/campaigns/train_30min_proper/enhanced_metrics.jsonl")
df_train = load_metrics(train_path, "NeuroFuzz (Training)")
print(f"Training: {len(df_train)} rows")

run_path = Path("data/campaigns/run_30min_proper/enhanced_metrics.jsonl")
df_run = load_metrics(run_path, "NeuroFuzz (Trained)")
print(f"Run: {len(df_run)} rows")

if not df_base.empty:
    print("Baseline Head:\n", df_base.head())
if not df_train.empty:
    print("Training Head:\n", df_train.head())
if not df_run.empty:
    print("Run Head:\n", df_run.head())

