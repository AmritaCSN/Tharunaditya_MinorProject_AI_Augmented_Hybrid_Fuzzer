from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from pathlib import Path
import yaml

class GeneralConfig(BaseModel):
    mode: str = Field(..., pattern="^(train|run|analyze)$")
    campaign_name: str = "default_campaign"
    log_level: str = "INFO"
    strict_checks: bool = False

class BinaryConfig(BaseModel):
    target_path: str
    
    @field_validator('target_path')
    @classmethod
    def validate_target_path(cls, v: str):
        # We don't strictly enforce existence here because it might be created later
        # or might be a relative path resolved at runtime.
        if not v or not v.strip():
            raise ValueError("target_path cannot be empty")
        return v

class AnalysisConfig(BaseModel):
    max_functions: int = 100
    timeout_per_function: int = 30

class AFLConfig(BaseModel):
    input_dir: str = "data/inputs"
    output_dir: str = "data/outputs"
    timeout_ms: int = 1000
    resume: bool = False
    force_clean: bool = False
    prompt_on_clean: bool = False
    backup_on_clean: bool = False

class SymbolicExecutionConfig(BaseModel):
    enable: bool = True
    max_states: int = 100
    max_depth: int = 50
    timeout_seconds: int = 300
    soft_timeout_seconds: int = 60

class EnergyEstimationConfig(BaseModel):
    base_watts: float = 45.0
    max_watts: float = 115.0
    measurement_source: str = "psutil_estimate"
    use_rapl_if_available: bool = False
    rapl_label: Optional[str] = None

class RLTrainingConfig(BaseModel):
    time_limit_minutes: int = 30
    learning_rate: float = 0.0003
    step_duration_seconds: int = 30

class RLCampaignConfig(BaseModel):
    max_steps: int = 50
    time_limit_minutes: Optional[int] = None

class RLConfig(BaseModel):
    training: RLTrainingConfig = Field(default_factory=RLTrainingConfig)
    campaign: RLCampaignConfig = Field(default_factory=RLCampaignConfig)
    model_path: str = "data/models/neurofuzz_model.zip"

class NeuroFuzzConfig(BaseModel):
    general: GeneralConfig
    binary: BinaryConfig
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    afl: AFLConfig = Field(default_factory=AFLConfig)
    symbolic_execution: SymbolicExecutionConfig = Field(default_factory=SymbolicExecutionConfig)
    reinforcement_learning: RLConfig = Field(default_factory=RLConfig)
    energy_estimation: EnergyEstimationConfig = Field(default_factory=EnergyEstimationConfig)

    @classmethod
    def load(cls, config_path: str) -> 'NeuroFuzzConfig':
        """Load and validate configuration from a YAML file."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
            
        with open(path, 'r') as f:
            raw_config = yaml.safe_load(f)
            
        return cls(**raw_config)
