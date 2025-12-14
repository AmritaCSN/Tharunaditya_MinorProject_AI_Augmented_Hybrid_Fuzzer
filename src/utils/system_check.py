import shutil
import sys
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class SystemCheck:
    """
    Performs system health checks before starting the fuzzer.
    When strict=True, warnings about core_pattern/CPU governor become failures.
    """
    
    @staticmethod
    def check_afl_installed() -> bool:
        """Check if afl-fuzz is in the PATH."""
        if shutil.which("afl-fuzz") is None:
            logger.error("❌ 'afl-fuzz' not found in PATH. Please install AFL++.")
            return False
        return True

    @staticmethod
    def check_core_pattern(strict: bool = False) -> bool:
        """
        Check /proc/sys/kernel/core_pattern.
        AFL++ requires this to NOT be sent to an external handler (like apport).
        It should ideally be 'core'.
        """
        core_pattern_path = Path("/proc/sys/kernel/core_pattern")
        if not core_pattern_path.exists():
            logger.warning("⚠️ Could not check core_pattern (file not found). Are you on WSL?")
            return True # Assume OK if we can't check (e.g. restricted container)

        try:
            content = core_pattern_path.read_text().strip()
            if content.startswith("|"):
                logger.warning(f"⚠️ System core_pattern is set to pipe: '{content}'")
                logger.warning("   AFL++ performance will be severely impacted.")
                logger.warning("   Run: 'echo core | sudo tee /proc/sys/kernel/core_pattern'")
                return False if strict else True
            
            if content != "core":
                logger.info(f"ℹ️ System core_pattern is '{content}'. Recommended: 'core'")
                if strict:
                    logger.warning("Strict mode: treating non-'core' core_pattern as failure")
                    return False
                
        except PermissionError:
            logger.warning("⚠️ Permission denied reading /proc/sys/kernel/core_pattern")
            
        return True

    @staticmethod
    def check_cpu_scaling(strict: bool = False) -> bool:
        """
        Check CPU scaling governor.
        AFL++ prefers 'performance'.
        """
        # This is complex to check on all cores, just a basic check
        scaling_path = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        if scaling_path.exists():
            try:
                governor = scaling_path.read_text().strip()
                if governor != "performance":
                    logger.warning(f"⚠️ CPU governor is '{governor}'. AFL++ prefers 'performance'.")
                    if strict:
                        logger.warning("Strict mode: treating non-performance governor as failure")
                        return False
                    return True
            except:
                pass
        return True

    @classmethod
    def run_all_checks(cls, strict: bool = False, apply_fixes: bool = False) -> bool:
        """Run all system checks. Returns True if critical checks pass.

        If apply_fixes is True, emit the exact commands needed. We do NOT auto-exec sudo.
        """
        print("Running System Checks...")
        issues = []
        passed = True
        if not cls.check_afl_installed():
            passed = False
            issues.append("install_afl")
            
        if not cls.check_core_pattern(strict=strict):
            passed = False
            issues.append("core_pattern")
        if not cls.check_cpu_scaling(strict=strict):
            passed = False
            issues.append("cpu_governor")
        
        if passed:
            print("✓ System checks passed")
        else:
            print("❌ System checks failed")
            cls.log_fix_instructions(strict=strict)
            if apply_fixes:
                cls.emit_fix_commands(issues)
            
        return passed

    @staticmethod
    def log_fix_instructions(strict: bool = False) -> None:
        """Log a concise checklist of remedial steps without executing them."""
        logger.info("System check checklist (manual steps):")
        logger.info("  - Install AFL++: sudo apt install afl++")
        logger.info("  - Set core_pattern: echo core | sudo tee /proc/sys/kernel/core_pattern")
        logger.info("  - Set CPU governor to performance (optional): sudo cpupower frequency-set -g performance")
        if strict:
            logger.info("Strict mode enforced: resolve the above before rerunning NeuroFuzz")

    @staticmethod
    def emit_fix_commands(issues):
        """Print actionable commands for requested fixes (no sudo execution)."""
        logger.info("Suggested remediation commands (not executed):")
        for issue in issues:
            if issue == "install_afl":
                logger.info("  sudo apt install afl++")
            if issue == "core_pattern":
                logger.info("  echo core | sudo tee /proc/sys/kernel/core_pattern")
            if issue == "cpu_governor":
                logger.info("  sudo cpupower frequency-set -g performance")
