#!/usr/bin/env python3
"""
NeuroFuzz Entry Point
"""

import argparse
import logging
import sys
from pathlib import Path

try:
    from src.core.config import NeuroFuzzConfig
    from src.core.orchestrator import NeuroFuzzOrchestrator
    from src.utils.system_check import SystemCheck
except ModuleNotFoundError as exc:
    missing = exc.name
    print(
        "Failed to import NeuroFuzz modules. Make sure the package is installed (pip install -e .) "
        "or set PYTHONPATH=. before running. Missing module: %s" % missing
    )
    sys.exit(1)

def setup_logging(log_level: str):
    """Configure logging."""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('neurofuzz.log')
        ],
        force=True
    )

def main():
    parser = argparse.ArgumentParser(description="NeuroFuzz: AI-Augmented Hybrid Fuzzer")
    parser.add_argument("--config", required=True, help="Path to configuration YAML file")
    parser.add_argument("--apply-fixes", action="store_true", help="Emit remediation commands for system checks")
    args = parser.parse_args()

    try:
        # 1. Load and Validate Configuration (do this first to use strict flag and log level)
        print(f"Loading configuration from {args.config}...")
        config = NeuroFuzzConfig.load(args.config)
        print("✓ Configuration validated successfully")

        # 2. Setup Logging
        setup_logging(config.general.log_level)
        logger = logging.getLogger(__name__)
        logger.info(f"Starting NeuroFuzz in {config.general.mode} mode")

        # 3. System Checks (respect strict flag from config)
        if not SystemCheck.run_all_checks(strict=config.general.strict_checks, apply_fixes=args.apply_fixes):
            sys.exit(1)

        # 4. Initialize Orchestrator
        orchestrator = NeuroFuzzOrchestrator()
        
        # Convert Pydantic model to dict for internal use
        # Pydantic v2 uses model_dump(), v1 uses dict()
        # We'll try model_dump first (v2), fall back to dict (v1)
        try:
            config_dict = config.model_dump()
        except AttributeError:
            config_dict = config.dict()
            
        orchestrator.initialize(config_dict)

        # 5. Execute based on mode
        try:
            orchestrator.run_campaign(config.general.mode)
        except ValueError as e:
            logger.error(f"ValueError during campaign: {e}")
            logging.exception("Campaign ValueError traceback")
            sys.exit(1)

    except Exception as e:
        print(f"\n❌ Fatal Error: {e}")
        logging.exception("Fatal error")
        sys.exit(1)

if __name__ == "__main__":
    main()
