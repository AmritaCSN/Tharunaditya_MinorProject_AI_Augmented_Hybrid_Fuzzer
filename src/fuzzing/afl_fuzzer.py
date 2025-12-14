"""
AFL++ Fuzzer Interface
"""

import os
import subprocess
import time
import logging
from pathlib import Path
from typing import Optional

from src.core.interfaces import IFuzzer, FuzzingStats


class AFLFuzzer(IFuzzer):
    """Interface to AFL++ coverage-guided fuzzer."""
    
    def __init__(self, afl_binary: str = "afl-fuzz"):
        """
        Initialize AFL++ fuzzer.
        
        Args:
            afl_binary: Path to afl-fuzz binary (default: "afl-fuzz" from PATH)
        """
        self.afl_binary = afl_binary
        self.process: Optional[subprocess.Popen] = None
        self.binary_path: Optional[str] = None
        self.output_dir: Optional[str] = None
        self.stderr_file = None  # File handle for AFL++ stderr
        self.logger = logging.getLogger(__name__)
        self.resume: bool = False  # When True, attempt to resume existing AFL++ state
        self.force_clean: bool = False  # When True, allow destructive cleanup on fresh runs
        self.prompt_on_clean: bool = False
        self.backup_on_clean: bool = False
        
        # Check if AFL++ is available
        if not self._check_afl_available():
            raise RuntimeError("AFL++ not found. Install with: sudo apt install afl++")
    
    def _check_afl_available(self) -> bool:
        """Check if AFL++ is installed."""
        try:
            result = subprocess.run(
                [self.afl_binary, "-h"],
                capture_output=True,
                timeout=5
            )
            return result.returncode in [0, 1]  # AFL returns 1 for -h
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def start(self, binary_path: str, input_dir: str, output_dir: str, timeout_ms: int = 1000) -> bool:
        """
        Start AFL++ fuzzer.
        
        Args:
            binary_path: Path to target binary
            input_dir: Directory with seed inputs
            output_dir: Directory for AFL++ output
            timeout_ms: Execution timeout in milliseconds
            
        Returns:
            True if started successfully
        """
        self.logger.info(f"Starting AFL++ fuzzer on {binary_path}")
        
        # Convert ALL paths to absolute (AFL++ requires absolute paths)
        binary_path = str(Path(binary_path).resolve())
        input_dir = str(Path(input_dir).resolve())  # Make input dir absolute
        output_dir = str(Path(output_dir).resolve())  # Make output dir absolute
        
        # Validate inputs
        if not Path(binary_path).exists():
            self.logger.error(f"Binary not found: {binary_path}")
            return False
        
        input_path = Path(input_dir)
        output_path = Path(output_dir)  # Use the absolute output_dir

        # Handle resume mode: if enabled and prior state exists, do NOT delete output
        resume_mode = self.resume and (output_path / "default").exists()
        if self.resume and not resume_mode:
            self.logger.info("Resume requested but no existing AFL++ state found; starting fresh run")
        if resume_mode and not self._validate_resume_state(output_path):
            self.logger.warning("Resume requested but AFL++ state looks invalid; falling back to fresh start")
            resume_mode = False
        
        if not resume_mode:
            if not input_path.exists() or not list(input_path.iterdir()):
                self.logger.error(f"Input directory empty or missing: {input_dir}")
                return False
        else:
            self.logger.info("Resume mode: skipping seed directory validation (using existing queue)")

        # CRITICAL: AFL++ fails if output directory has stale state when not resuming
        if output_path.exists() and not resume_mode:
            if not self.force_clean:
                self.logger.error(
                    "Output directory exists and resume=false but force_clean is disabled. "
                    "Refusing to delete existing AFL++ state. Enable afl.force_clean=true to proceed or set resume=true."
                )
                return False

            if self.prompt_on_clean:
                print(f"AFL output directory exists: {output_path}")
                print("Cleaning will delete prior AFL++ state. Type 'YES' to continue:", end=' ', flush=True)
                user_input = input().strip()
                if user_input != 'YES':
                    self.logger.info("User declined cleanup; aborting start.")
                    return False

            if self.backup_on_clean:
                backup_path = output_path.with_suffix('.bak')
                try:
                    import shutil
                    if backup_path.exists():
                        shutil.rmtree(backup_path, ignore_errors=True)
                    shutil.copytree(output_path, backup_path)
                    self.logger.info(f"Backed up AFL output to {backup_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to backup AFL output: {e}")

            self.logger.warning(
                "Output directory exists and resume=false; cleaning will delete prior AFL++ state. "
                "Set afl.resume=true to reuse the existing queue."
            )
            import shutil
            import time

            try:
                # Remove ALL files including lock files, fuzzer_stats, .cur_input, etc.
                self.logger.info(f"Cleaning output directory: {output_path}")
                shutil.rmtree(output_path, ignore_errors=False)
                time.sleep(0.1)  # Give filesystem time to sync
                self.logger.info("✓ Output directory cleaned successfully")
            except PermissionError as e:
                # If permission denied, try to remove just the default/ subdirectory
                self.logger.warning(f"Permission error cleaning full output dir: {e}")
                default_dir = output_path / 'default'
                if default_dir.exists():
                    try:
                        shutil.rmtree(default_dir, ignore_errors=False)
                        self.logger.info("✓ Cleaned default/ subdirectory")
                    except Exception as e2:
                        self.logger.error(f"Cannot clean output directory: {e2}")
                        return False
            except Exception as e:
                self.logger.error(f"Failed to clean output directory: {e}")
                return False
        
        # Create output directory if missing
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Verify we can write to output directory (prevents silent failures)
        test_file = output_path / ".neurofuzz_write_test"
        try:
            test_file.write_text("test")
            test_file.unlink()
        except Exception as e:
            self.logger.error(f"Cannot write to output directory: {e}")
            return False
        
        # Build AFL++ command with absolute paths
        # Resume requires -i - and existing queue; otherwise normal input dir
        cmd_input_dir = input_dir
        if resume_mode:
            cmd_input_dir = "-"
            self.logger.info("AFL++ resume mode enabled: using existing queue in output directory")
        
        # NOTE: Using stdin mode (no @@) to prevent temp file creation in project root
        cmd = [
            self.afl_binary,
            "-i", cmd_input_dir,
            "-o", output_dir,
            "-m", "none",
            "-t", str(timeout_ms),
            "--",
            binary_path  # Binary reads from stdin (no @@ = clean execution)
        ]
        
        # Set AFL++ environment variables (industry-standard configuration)
        env = os.environ.copy()
        env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'  # Suppress crash warnings
        env['AFL_SKIP_CPUFREQ'] = '1'  # Skip CPU frequency check (VM compatibility)
        env['AFL_NO_UI'] = '1'  # Non-interactive mode (required for subprocess)
        env['AFL_SKIP_BIN_CHECK'] = '1'  # Skip binary instrumentation check
        env['AFL_TESTCACHE_SIZE'] = '50'  # Cache size for test cases
        env['AFL_TMPDIR'] = str(output_path)  # Force AFL++ to use output dir for temp files
        env['AFL_IGNORE_SEED_PROBLEMS'] = '1'  # Skip crashes/timeouts in seeds (cgc_cadet has intentional crash seeds)
        # NOTE: Removed AFL_AUTORESUME - we always start fresh to avoid conflicts
        
        try:
            # Start AFL++ process - redirect stderr to file for debugging
            stderr_log = Path("/tmp/afl_stderr.txt")
            self.logger.info(f"AFL++ command: {' '.join(cmd)}")
            self.logger.info(f"AFL++ stderr will be written to: {stderr_log}")
            
            # Keep file handle open for duration of process
            self.stderr_file = open(stderr_log, 'w', buffering=1)  # Line buffered
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=self.stderr_file,
                env=env
                # Note: All paths are absolute, no cwd needed
                # Crash artifacts will go to AFL++ output directory
            )
            
            self.binary_path = binary_path
            self.output_dir = output_dir
            
            # Check immediately if process started (common failure point)
            time.sleep(0.5)
            if self.process.poll() is not None:
                exit_code = self.process.returncode
                self.logger.error(f"AFL++ exited immediately with code {exit_code}")
                
                # Detailed error reporting to diagnose AFL++ failures
                self.logger.error("Common causes:")
                self.logger.error("  1. Binary not AFL++-instrumented (compile with afl-clang-fast)")
                self.logger.error("  2. Input directory empty or contains invalid files")
                self.logger.error("  3. Output directory permission issues")
                self.logger.error("  4. Binary requires specific input format (check with manual test)")
                self.logger.error("  5. Core pattern not set (echo core | sudo tee /proc/sys/kernel/core_pattern)")
                
                # Read stderr for detailed AFL++ error message
                try:
                    with open(stderr_log, 'r') as f:
                        stderr_output = f.read()
                        if stderr_output:
                            self.logger.error(f"AFL++ stderr output:\n{stderr_output}")
                except Exception as e:
                    self.logger.error(f"Could not read stderr log: {e}")
                
                # Provide actionable recovery steps
                self.logger.error("\nDebugging steps:")
                self.logger.error(f"  1. Test binary manually: {binary_path} {input_dir}/seed_*.txt")
                self.logger.error(f"  2. Test AFL++ manually: afl-fuzz -i {input_dir} -o /tmp/test_afl_out -- {binary_path} @@")
                self.logger.error(f"  3. Check AFL++ version: afl-fuzz -V")
                
                return False
            
            # Wait for AFL++ to initialize (reduced for faster startup)
            self.logger.info("Waiting for AFL++ initialization (2 seconds)...")
            time.sleep(2)
            
            # Check if fuzzer is actually running
            if self.is_running():
                self.logger.info("AFL++ fuzzer started successfully")
                return True
            else:
                self.logger.error("AFL++ failed to start")
                # Read stderr from file
                try:
                    if stderr_log.exists():
                        with open(stderr_log, 'r') as f:
                            stderr_output = f.read()
                            if stderr_output:
                                self.logger.error(f"AFL++ stderr output:\n{stderr_output}")
                except Exception as e:
                    self.logger.error(f"Could not read stderr file: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start AFL++: {e}")
            return False
    
    def stop(self) -> None:
        """Stop AFL++ fuzzer."""
        if self.process:
            self.logger.info("Stopping AFL++ fuzzer")
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        
        # Close stderr file if open
        if self.stderr_file:
            try:
                self.stderr_file.close()
            except Exception:
                pass
            self.stderr_file = None
    
    def get_stats(self) -> FuzzingStats:
        """
        Get current fuzzing statistics from AFL++ stats file.
        
        Returns:
            FuzzingStats object
        """
        if not self.output_dir:
            return self._empty_stats()
        
        stats_file = Path(self.output_dir) / "default" / "fuzzer_stats"
        
        if not stats_file.exists():
            return self._empty_stats()
        
        try:
            # Parse AFL++ stats file
            stats_data = {}
            with open(stats_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        stats_data[key.strip()] = value.strip()
            
            # Extract relevant metrics (AFL++ v4.x field names)
            total_execs = int(stats_data.get('execs_done', 0))
            exec_speed = float(stats_data.get('execs_per_sec', 0.0))
            corpus_count = int(stats_data.get('corpus_count', 0))  # Queue files (new coverage)
            crashes = int(stats_data.get('saved_crashes', 0))  # Unique crashes
            hangs = int(stats_data.get('saved_hangs', 0))  # Unique hangs
            time_elapsed = int(stats_data.get('last_update', 0))
            
            # For RL reward: Use corpus_count as paths_total (exploration signal)
            # Crashes are rewarded separately in environment.py (+1.0 vs +0.2)
            # Including crashes here would double-count them in the reward
            paths_total = corpus_count
            
            # Coverage percentage from bitmap
            bitmap_cvg_str = stats_data.get('bitmap_cvg', '0.00%').rstrip('%')
            coverage_pct = float(bitmap_cvg_str)
            
            # Track new paths/crashes (simple diff from last known state)
            if hasattr(self, '_last_paths'):
                new_paths = paths_total - self._last_paths
                new_crashes = crashes - self._last_crashes
            else:
                new_paths = paths_total
                new_crashes = crashes
            
            self._last_paths = paths_total
            self._last_crashes = crashes
            
            return FuzzingStats(
                total_executions=total_execs,
                exec_speed=exec_speed,
                paths_total=paths_total,
                paths_new=new_paths,
                crashes_total=crashes,
                crashes_new=new_crashes,
                coverage_percentage=coverage_pct,
                time_elapsed=time_elapsed
            )
            
        except Exception as e:
            self.logger.error(f"Failed to read stats: {e}")
            return self._empty_stats()
    
    def is_running(self) -> bool:
        """Check if AFL++ fuzzer is running."""
        if not self.process:
            return False
        
        # Check process is alive
        poll_result = self.process.poll()
        if poll_result is not None:
            self.logger.warning(f"AFL++ process exited with code {poll_result}")
            return False
        
        # Verify stats file exists and is reasonably recent
        # Use 120-second timeout (was 30) to handle heavy symbolic execution periods
        if self.output_dir:
            stats_file = Path(self.output_dir) / "default" / "fuzzer_stats"
            if stats_file.exists():
                age = time.time() - stats_file.stat().st_mtime
                if age > 120:  # 2 minutes tolerance
                    self.logger.warning(f"AFL++ stats file is stale ({age:.0f}s old) but process alive")
                    # Still return True if process is alive, just warn
                return True
            else:
                # Stats file doesn't exist yet - might be initializing
                return True
        
        return True
    
    def _empty_stats(self) -> FuzzingStats:
        """Return empty stats object."""
        return FuzzingStats(
            total_executions=0,
            exec_speed=0.0,
            paths_total=0,
            paths_new=0,
            crashes_total=0,
            crashes_new=0,
            coverage_percentage=0.0,
            time_elapsed=0.0
        )

    def _validate_resume_state(self, output_path: Path) -> bool:
        """Sanity-check AFL++ output directory before resuming."""
        default_dir = output_path / "default"
        queue_dir = default_dir / "queue"
        stats_file = default_dir / "fuzzer_stats"

        if not default_dir.exists():
            self.logger.warning("Resume requested but default/ dir is missing")
            return False

        if not queue_dir.exists() or not any(queue_dir.iterdir()):
            self.logger.warning("Resume requested but queue/ is missing or empty; cannot resume")
            return False

        if not stats_file.exists():
            self.logger.warning("Resume requested but fuzzer_stats is missing; cannot resume")
            return False

        return True
