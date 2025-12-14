import pytest
from pathlib import Path
import yaml
from src.core.config import NeuroFuzzConfig

def test_valid_config(tmp_path):
    """Test loading a valid configuration file."""
    config_data = {
        "general": {
            "mode": "train",
            "campaign_name": "test_campaign"
        },
        "binary": {
            "target_path": "/bin/ls"
        },
        "reinforcement_learning": {
            "training": {
                "time_limit_minutes": 10
            }
        }
    }
    
    config_file = tmp_path / "valid_config.yml"
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
        
    config = NeuroFuzzConfig.load(str(config_file))
    assert config.general.mode == "train"
    assert config.binary.target_path == "/bin/ls"
    assert config.reinforcement_learning.training.time_limit_minutes == 10

def test_invalid_mode(tmp_path):
    """Test that invalid mode raises validation error."""
    config_data = {
        "general": {
            "mode": "invalid_mode",  # Invalid
            "campaign_name": "test"
        },
        "binary": {
            "target_path": "/bin/ls"
        }
    }
    
    config_file = tmp_path / "invalid_mode.yml"
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
        
    with pytest.raises(ValueError):
        NeuroFuzzConfig.load(str(config_file))

def test_missing_required_field(tmp_path):
    """Test that missing required field raises validation error."""
    config_data = {
        "general": {
            "mode": "train"
        }
        # Missing 'binary' section
    }
    
    config_file = tmp_path / "missing_field.yml"
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
        
    with pytest.raises(ValueError):
        NeuroFuzzConfig.load(str(config_file))

def test_empty_target_path(tmp_path):
    """Test that empty target path raises validation error."""
    config_data = {
        "general": {
            "mode": "train",
            "campaign_name": "test"
        },
        "binary": {
            "target_path": "   "  # Empty/Whitespace
        }
    }
    
    config_file = tmp_path / "empty_path.yml"
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)
        
    with pytest.raises(ValueError, match="target_path cannot be empty"):
        NeuroFuzzConfig.load(str(config_file))
