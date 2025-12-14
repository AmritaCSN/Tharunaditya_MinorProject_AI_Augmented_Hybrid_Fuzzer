"""
Symbolic Executor using angr with ROBUST DRILLER-INSPIRED CONCOLIC EXECUTION
- Selective symbolization (only critical bytes)
- Proper stdin/file handling
- Constraint simplification & pruning
- Multi-strategy fallbacks
- Comprehensive error recovery
"""

import angr
import claripy
import logging
import signal
import time
import os
import traceback
from typing import Optional, List, Tuple
from pathlib import Path

from angr.calling_conventions import SimFunctionArgument

from src.core.interfaces import ISymbolicExecutor, BinaryTarget


logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('angr.storage.memory_mixins').setLevel(logging.CRITICAL)

MODULE_LOGGER = logging.getLogger(__name__)


def _patch_calling_convention_tuple_handling() -> None:
    """Monkey patch angr calling convention to tolerate tuple return values."""
    current = SimFunctionArgument.check_value_set
    if getattr(current, '_neurofuzz_patched', False):
        return

    original_check_value_set = current

    def patched(self, value, arch):  # type: ignore[override]
        if isinstance(value, tuple):
            MODULE_LOGGER.debug("[SYMEX-PATCH] Flattening tuple return from SimProcedure")
            flattened = None
            for element in value:
                if isinstance(element, claripy.ast.Base):
                    flattened = element
                    break
            if flattened is None:
                flattened = value[0] if value else 0
            if isinstance(flattened, (bytes, bytearray)):
                data = bytes(flattened)
                bit_len = len(data) * 8
                if self.size is not None:
                    max_bits = self.size * arch.byte_width
                    if bit_len > max_bits:
                        data = data[: max_bits // 8]
                        bit_len = max_bits
                    elif bit_len == 0 and max_bits:
                        bit_len = max_bits
                if bit_len == 0:
                    bit_len = arch.byte_width
                    data = b"\x00"
                flattened = claripy.BVV(int.from_bytes(data, byteorder='big', signed=False), bit_len)
            elif isinstance(flattened, tuple):
                flattened = flattened[0] if flattened else 0
            value = flattened

        if isinstance(value, claripy.ast.Base) and self.size is not None:
            max_bits = self.size * arch.byte_width
            current_bits = value.size()
            if current_bits > max_bits:
                MODULE_LOGGER.debug(
                    f"[SYMEX-PATCH] Truncating BV from {current_bits} to {max_bits} bits for argument size {self.size}"
                )
                value = claripy.Extract(current_bits - 1, current_bits - max_bits, value)
            elif current_bits < max_bits:
                MODULE_LOGGER.debug(
                    f"[SYMEX-PATCH] Zero-extending BV from {current_bits} to {max_bits} bits for argument size {self.size}"
                )
                value = claripy.ZeroExt(max_bits - current_bits, value)

        return original_check_value_set(self, value, arch)

    patched._neurofuzz_patched = True  # type: ignore[attr-defined]
    SimFunctionArgument.check_value_set = patched


_patch_calling_convention_tuple_handling()


class SymbolicExecutor(ISymbolicExecutor):
    """Robust symbolic execution with Driller-inspired concolic execution."""
    
    def __init__(
        self,
        binary_path: str,
        max_depth: int = 50,
        max_states: int = 256,
        timeout_seconds: int = 300,
        symbolic_buffer_size: int = 256,
        soft_timeout_seconds: int = 120,
        use_crash_exploration: bool = True,
        selective_symbolization: bool = True,
        max_symbolic_bytes: int = 256
    ):
        """
        Initialize robust symbolic executor.
        
        Args:
            binary_path: Path to binary
            max_depth: Maximum exploration depth
            max_states: Maximum number of states to explore
            timeout_seconds: Hard timeout for symbolic execution
            symbolic_buffer_size: Maximum size of input buffer
            soft_timeout_seconds: Soft timeout for exploration
            use_crash_exploration: Use crash-directed exploration
            selective_symbolization: Only symbolize critical bytes (Driller-style)
            max_symbolic_bytes: Maximum bytes to symbolize (reduce constraint complexity)
        """
        self.binary_path = binary_path
        self.max_depth = max_depth
        self.max_states = max_states
        self.timeout_seconds = timeout_seconds
        self.symbolic_buffer_size = symbolic_buffer_size
        self.soft_timeout_seconds = soft_timeout_seconds
        self.use_crash_exploration = use_crash_exploration
        self.selective_symbolization = selective_symbolization
        self.max_symbolic_bytes = max_symbolic_bytes
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.total_attempts = 0
        self.successful_solves = 0
        self.failed_solves = 0
        
        # Try to use clean (non-ASAN) binary for faster exploration
        self.symex_binary = self._find_clean_binary(binary_path)
        
        # Load project once
        try:
            self.project = angr.Project(
                self.symex_binary,
                auto_load_libs=False,
                load_options={'auto_load_libs': False}
            )
            self.logger.info(f"Loaded binary for symex: {self.symex_binary}")
            if self.symex_binary != binary_path:
                self.logger.info(f"  (using clean version instead of {binary_path})")
        except Exception as e:
            self.logger.error(f"Failed to load binary: {e}")
            raise

    def _find_clean_binary(self, binary_path: str) -> str:
        """Find clean (non-ASAN) version of binary for faster symex."""
        path = Path(binary_path)
        
        # If binary ends with _instrumented, try clean version
        if path.name.endswith('_instrumented'):
            clean_name = path.name.replace('_instrumented', '_clean')
            clean_path = path.parent / clean_name
            if clean_path.exists():
                return str(clean_path)
        
        return binary_path
    
    def find_input_for_target(self, target: BinaryTarget, seed_input: Optional[bytes] = None) -> Optional[bytes]:
        """
        ROBUST symbolic execution with multi-strategy approach.
        
        Strategy:
        1. Selective symbolization (Driller-style): start with concrete seed, symbolize only N bytes
        2. Proper stdin handling: use SimFile correctly with read() syscalls
        3. Constraint simplification: eagerly simplify constraints
        4. Multi-strategy fallback: if crash-directed fails, try targeted exploration
        5. Comprehensive error recovery: catch all angr exceptions
        
        Args:
            target: BinaryTarget to reach or crash at
            seed_input: Optional concrete seed input from AFL queue (Driller-style)
            
        Returns:
            Input bytes that cause crash/reach target, or None if not found
        """
        self.total_attempts += 1
        self.logger.info(f"[SYMEX] Attempt #{self.total_attempts} - Target: {target.name} @ {hex(target.address)}")
        self.logger.info(f"[SYMEX] Strategy: {'SELECTIVE-SYMBOLIC' if seed_input and self.selective_symbolization else 'FULL-SYMBOLIC'}")
        
        start_time = time.time()
        
        # Try multiple strategies with fallbacks
        strategies = [
            ('crash_directed', self._crash_directed_exploration),
            ('targeted_address', self._targeted_address_exploration),
            ('full_symbolic_fallback', self._full_symbolic_fallback),
        ]
        
        for strategy_name, strategy_func in strategies:
            try:
                result = strategy_func(target, seed_input, start_time)
                if result:
                    self.successful_solves += 1
                    elapsed = time.time() - start_time
                    self.logger.info(f"[SYMEX] ✓ Success with {strategy_name} in {elapsed:.1f}s")
                    self.logger.info(f"[SYMEX] Stats: {self.successful_solves}/{self.total_attempts} success rate")
                    return result
            except Exception as e:
                self.logger.warning(f"[SYMEX] Strategy {strategy_name} failed: {e}")
                continue
        
        # All strategies failed
        self.failed_solves += 1
        elapsed = time.time() - start_time
        self.logger.info(f"[SYMEX] ✗ All strategies failed in {elapsed:.1f}s")
        return None
    
    def _crash_directed_exploration(self, target: BinaryTarget, seed_input: Optional[bytes], start_time: float) -> Optional[bytes]:
        """Crash-directed exploration: find errored/unconstrained states."""
        if not self.use_crash_exploration:
            return None
        
        self.logger.info(f"[SYMEX-CRASH] Exploring for crashes...")
        
        with self._time_limit(self.soft_timeout_seconds):
            # Create initial state with proper stdin handling
            state = self._create_initial_state(seed_input)
            
            if not state:
                return None
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Run exploration looking for crashes
            try:
                simgr.run(
                    timeout=self.soft_timeout_seconds,
                    until=lambda sm: len(sm.errored) > 0 or len(sm.unconstrained) > 0,
                    step_func=self._prune_states_callback
                )
            except TimeoutError:
                self.logger.warning(f"[SYMEX-CRASH] Timed out after {self.soft_timeout_seconds}s")
                raise  # Re-raise to notify orchestrator
            except Exception as e:
                self.logger.warning(f"[SYMEX-CRASH] Exploration error: {e}")
                self.logger.warning(traceback.format_exc())
                return None
            
            elapsed = time.time() - start_time
            self.logger.info(f"[SYMEX-CRASH] Completed in {elapsed:.1f}s")
            self.logger.info(f"[SYMEX-CRASH]   Errored: {len(simgr.errored)}, Unconstrained: {len(simgr.unconstrained)}")
            self.logger.info(f"[SYMEX-CRASH]   Active: {len(simgr.active)}, Deadended: {len(simgr.deadended)}")
            
            # Try errored states first (crashes)
            result = self._extract_input_from_errored_states(simgr.errored)
            if result:
                return result
            
            # Try unconstrained states (control flow hijack)
            result = self._extract_input_from_unconstrained_states(simgr.unconstrained)
            if result:
                return result
            
            return None
    
    def _targeted_address_exploration(self, target: BinaryTarget, seed_input: Optional[bytes], start_time: float) -> Optional[bytes]:
        """Targeted exploration: try to reach specific address."""
        self.logger.info(f"[SYMEX-TARGET] Exploring to address {hex(target.address)}...")
        
        with self._time_limit(self.soft_timeout_seconds):
            # Create initial state
            state = self._create_initial_state(seed_input)
            
            if not state:
                return None
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Resolve avoid addresses
            avoid_addrs = self._resolve_avoid_addresses(target.avoid_functions)
            
            try:
                simgr.explore(
                    find=target.address,
                    avoid=avoid_addrs,
                    num_find=1,
                    step_func=self._prune_states_callback
                )
            except TimeoutError:
                self.logger.warning(f"[SYMEX-TARGET] Timed out after {self.soft_timeout_seconds}s")
                raise  # Re-raise to notify orchestrator
            except Exception as e:
                self.logger.warning(f"[SYMEX-TARGET] Exploration error: {e}")
                self.logger.warning(traceback.format_exc())
                return None
            
            # Check if target was found
            if simgr.found:
                found_state = simgr.found[0]
                result = self._extract_input_from_state(found_state)
                if result:
                    elapsed = time.time() - start_time
                    self.logger.info(f"[SYMEX-TARGET] Found input in {elapsed:.1f}s: {len(result)} bytes")
                    return result
            
            return None

    def _full_symbolic_fallback(self, target: BinaryTarget, seed_input: Optional[bytes], start_time: float) -> Optional[bytes]:
        """Fallback strategy: Full symbolic execution without preconstraints."""
        self.logger.info(f"[SYMEX-FALLBACK] Trying full symbolic execution (ignoring seed constraints)...")
        
        with self._time_limit(self.soft_timeout_seconds):
            # Create initial state WITHOUT preconstraints AND WITHOUT selective symbolization
            # We want FULL symbolic execution here
            state = self._create_initial_state(seed_input, preconstrain=False, selective_symbolization=False)
            
            if not state:
                return None
            
            simgr = self.project.factory.simulation_manager(state)
            avoid_addrs = self._resolve_avoid_addresses(target.avoid_functions)
            
            try:
                # Try to find target OR crash
                simgr.explore(
                    find=target.address,
                    avoid=avoid_addrs,
                    num_find=1,
                    step_func=self._prune_states_callback
                )
            except Exception as e:
                self.logger.warning(f"[SYMEX-FALLBACK] Error: {e}")
                return None
                
            if simgr.found:
                self.logger.info(f"[SYMEX-FALLBACK] Found target!")
                return self._extract_input_from_state(simgr.found[0])
            
            # Also check for crashes
            if simgr.errored:
                return self._extract_input_from_errored_states(simgr.errored)
            if simgr.unconstrained:
                return self._extract_input_from_unconstrained_states(simgr.unconstrained)
                
            return None

    
    def _create_initial_state(self, seed_input: Optional[bytes] = None, preconstrain: bool = True, selective_symbolization: Optional[bool] = None) -> Optional[angr.SimState]:
        """
        Create initial state with PROPER stdin handling.
        
        Handles:
        1. Selective symbolization (Driller-style concolic)
        2. Proper SimFile setup for stdin
        3. Correct file descriptor handling
        4. Constraint simplification options
        
        Args:
            seed_input: Optional concrete seed from AFL queue
            preconstrain: Whether to preconstrain symbolic bytes to seed values
            selective_symbolization: Override instance setting
            
        Returns:
            Initial state or None on failure
        """
        # Use instance setting if not overridden
        use_selective = self.selective_symbolization if selective_symbolization is None else selective_symbolization
        try:
            if seed_input:
                # Ensure we have enough space for exploration, even if seed is small
                # We want at least symbolic_buffer_size, or the seed length if it's larger
                input_size = max(len(seed_input), self.symbolic_buffer_size)
            else:
                input_size = self.symbolic_buffer_size

            if input_size <= 0:
                input_size = 1

            stdin_content = None

            if seed_input and use_selective:
                symbolic_bytes_count = min(self.max_symbolic_bytes, input_size, len(seed_input))
                concrete_size = max(input_size - symbolic_bytes_count, 0)
                concrete_prefix = seed_input[:concrete_size] if concrete_size > 0 else b''

                self.logger.debug(
                    f"[SYMEX-STATE] Selective symbolization: {symbolic_bytes_count}/{len(seed_input)} bytes symbolic"
                )

                symbolic_region = None
                if symbolic_bytes_count > 0:
                    # Create individual byte variables to help preconstrainer
                    # This avoids "not a leaf AST" errors when constraining slices
                    sym_bytes = [claripy.BVS(f'stdin_byte_{i}', 8) for i in range(symbolic_bytes_count)]
                    if sym_bytes:
                        symbolic_region = sym_bytes[0]
                        for b in sym_bytes[1:]:
                            symbolic_region = claripy.Concat(symbolic_region, b)

                concrete_bv = self._bytes_to_bv(concrete_prefix)

                if concrete_bv is not None and symbolic_region is not None:
                    stdin_content = claripy.Concat(concrete_bv, symbolic_region)
                elif concrete_bv is not None:
                    stdin_content = concrete_bv
                elif symbolic_region is not None:
                    stdin_content = symbolic_region

            # Removed incorrect 'elif seed_input:' block that forced concrete execution
            # If selective_symbolization is False, we fall through to full symbolization below

            if stdin_content is None:
                self.logger.debug(f"[SYMEX-STATE] Full symbolization: {input_size} bytes")
                # Create individual byte variables for full symbolization too
                sym_bytes = [claripy.BVS(f'stdin_byte_{i}', 8) for i in range(input_size)]
                if sym_bytes:
                    stdin_content = sym_bytes[0]
                    for b in sym_bytes[1:]:
                        stdin_content = claripy.Concat(stdin_content, b)
                else:
                    # Fallback for size 0
                    stdin_content = claripy.BVS('stdin', input_size * 8)

            state = self.project.factory.entry_state(
                add_options={
                    angr.options.LAZY_SOLVES,
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SIMPLIFY_MEMORY_WRITES,
                    angr.options.SIMPLIFY_REGISTER_WRITES,
                },
                remove_options={
                    angr.options.SUPPORT_FLOATING_POINT,
                },
                stdin=stdin_content
            )

            # stdin is already set up by entry_state in posix.fd[0]
            # Do NOT overwrite fd[0] with the SimFile object directly, as it breaks SimFileDescriptor abstraction

            # DRILLER-INSPIRED: Preconstrain symbolic bytes to concrete seed values
            # This acts as a "poor man's tracer", guiding execution along the seed's path
            # until constraints force deviation.
            if seed_input and preconstrain:
                try:
                    # Ensure we only preconstrain up to the size of the content we created
                    # The stdin_content might be smaller than seed_input if we truncated it
                    content_len = stdin_content.length // 8
                    constrain_bytes = seed_input[:content_len]
                    
                    self.logger.debug(f"[SYMEX-STATE] Preconstraining {len(constrain_bytes)} bytes to concrete values")
                    
                    if hasattr(state.preconstrainer, 'preconstrain_file'):
                         state.preconstrainer.preconstrain_file(constrain_bytes, state.posix.stdin, True)
                    else:
                        self.logger.debug("[SYMEX-STATE] Preconstrainer not available, skipping")

                except StopIteration:
                    self.logger.warning("[SYMEX-STATE] Preconstrainer hit StopIteration (trace divergence). Continuing with unconstrained state.")
                    # Do NOT raise or return None. Just continue with the state as-is.
                except Exception as e:
                    self.logger.warning(f"[SYMEX-STATE] Failed to preconstrain: {repr(e)}")
                    # Continue with state as-is


            if state.solver.constraints:
                state.solver.simplify()

            return state
            
        except Exception as e:
            self.logger.error(f"[SYMEX-STATE] Failed to create initial state: {e}")
            return None

    def _bytes_to_bv(self, data: bytes) -> Optional[claripy.ast.BV]:
        """Convert a byte string to a Claripy bit-vector without hitting raw_to_bv issues."""
        if not data:
            return None
        # Build in chunks to avoid huge integer conversions
        chunks = [claripy.BVV(byte, 8) for byte in data]
        if not chunks:
            return None
        result = chunks[0]
        for chunk in chunks[1:]:
            result = claripy.Concat(result, chunk)
        return result
    
    def _extract_input_from_state(self, state: angr.SimState) -> Optional[bytes]:
        """
        ROBUST extraction of concrete input from state.
        
        Tries multiple methods:
        1. state.posix.dumps(0) for stdin fd (most reliable)
        2. Direct solver evaluation of stdin symbolic variable
        3. state.posix.stdin content evaluation
        4. Fall back to reading file object
        
        Args:
            state: angr state to extract input from
            
        Returns:
            Concrete input bytes or None
        """
        try:
            # Method 1: Try posix.dumps(0) FIRST - most reliable for stdin
            try:
                concrete_input = state.posix.dumps(0)
                if concrete_input:
                    self.logger.debug(f"[SYMEX-EXTRACT] Method 1 (dumps): {len(concrete_input)} bytes")
                    return concrete_input
            except Exception as e:
                self.logger.debug(f"[SYMEX-EXTRACT] Method 1 failed: {e}")
            
            # Method 2: Try to find stdin symbolic variables and evaluate directly
            try:
                for var_name in ['stdin', 'stdin_symbolic']:
                    try:
                        variables = state.solver.get_variables(var_name) or []
                    except Exception:
                        continue
                    for var in variables:
                        concrete_val = state.solver.eval(var, cast_to=bytes)
                        if concrete_val:
                            self.logger.debug(
                                f"[SYMEX-EXTRACT] Method 2 (direct var {var_name}): {len(concrete_val)} bytes"
                            )
                            return concrete_val
            except Exception as e:
                self.logger.debug(f"[SYMEX-EXTRACT] Method 2 failed: {e}")
            
            # Method 3: Try stdin content (but DON'T access .content directly - causes tuple error)
            try:
                if hasattr(state, 'posix') and hasattr(state.posix, 'stdin'):
                    # Use SimFile.load() method instead of accessing .content
                    stdin_file = state.posix.stdin
                    if hasattr(stdin_file, 'load'):
                        # Load from offset 0
                        size = getattr(stdin_file, 'size', self.symbolic_buffer_size)
                        loaded_data = stdin_file.load(0, size)
                        if loaded_data is not None:
                            concrete_input = state.solver.eval(loaded_data, cast_to=bytes)
                            self.logger.debug(f"[SYMEX-EXTRACT] Method 3 (stdin.load): {len(concrete_input)} bytes")
                            return concrete_input
            except Exception as e:
                self.logger.debug(f"[SYMEX-EXTRACT] Method 3 failed: {e}")
            
            # Method 4: Last resort - read from fd 0
            try:
                if 0 in state.posix.fd:
                    fd_obj = state.posix.fd[0]
                    if hasattr(fd_obj, 'read'):
                        # Try to read from file
                        read_data = fd_obj.read(state.posix.fd[0].size if hasattr(fd_obj, 'size') else 1024)
                        if read_data and hasattr(read_data, 'symbolic'):
                            concrete_input = state.solver.eval(read_data, cast_to=bytes)
                            self.logger.debug(f"[SYMEX-EXTRACT] Method 4 (fd read): {len(concrete_input)} bytes")
                            return concrete_input
            except Exception as e:
                self.logger.debug(f"[SYMEX-EXTRACT] Method 4 failed: {e}")
            
            self.logger.warning(f"[SYMEX-EXTRACT] All extraction methods failed")
            return None
            
        except Exception as e:
            self.logger.error(f"[SYMEX-EXTRACT] Extraction error: {e}")
            return None
    
    def _extract_input_from_errored_states(self, errored_states: List) -> Optional[bytes]:
        """Extract input from errored states (crashes)."""
        if not errored_states:
            return None
        
        for err in errored_states[:5]:  # Try first 5 errors
            try:
                self.logger.debug(f"[SYMEX-ERRORED] Trying error: {err.error}")
                result = self._extract_input_from_state(err.state)
                if result:
                    self.logger.info(f"[SYMEX-ERRORED] ✓ Extracted crash input: {len(result)} bytes (Error: {err.error})")
                    return result
            except Exception as e:
                self.logger.debug(f"[SYMEX-ERRORED] Failed: {e}")
                continue
        
        return None
    
    def _extract_input_from_unconstrained_states(self, unconstrained_states: List) -> Optional[bytes]:
        """Extract input from unconstrained states (control flow hijack)."""
        if not unconstrained_states:
            return None
        
        for unc_state in unconstrained_states[:5]:  # Try first 5
            try:
                result = self._extract_input_from_state(unc_state)
                if result:
                    self.logger.info(f"[SYMEX-UNCONSTRAINED] ✓ Extracted hijack input: {len(result)} bytes")
                    return result
            except Exception as e:
                self.logger.debug(f"[SYMEX-UNCONSTRAINED] Failed: {e}")
                continue
        
        return None
    
    def _prune_states_callback(self, simgr: angr.SimulationManager) -> angr.SimulationManager:
        """
        Prune states to keep exploration focused.
        
        Pruning strategies:
        1. Limit total active states to max_states
        2. Drop states with high constraint complexity
        3. Prioritize states closer to target (if available)
        4. Simplify constraints periodically
        
        Args:
            simgr: Simulation manager
            
        Returns:
            Modified simulation manager
        """
        try:
            # Prune if too many active states
            if len(simgr.active) > self.max_states:
                # Sort by constraint complexity (fewer constraints = better)
                sorted_states = sorted(
                    simgr.active,
                    key=lambda s: len(s.solver.constraints)
                )
                
                # Keep only the best states
                simgr.active = sorted_states[:self.max_states]
                self.logger.debug(f"[SYMEX-PRUNE] Pruned to {len(simgr.active)} states")
            
            # Eagerly simplify constraints in active states
            for state in simgr.active:
                if len(state.solver.constraints) > 100:  # If too many constraints
                    try:
                        state.solver.simplify()
                    except:
                        pass
            
        except Exception as e:
            self.logger.debug(f"[SYMEX-PRUNE] Pruning error: {e}")
        
        return simgr
    
    def _time_limit(self, seconds: int):
        """Unix alarm-based timeout guard to prevent long-running symex."""
        def handler(signum, frame):
            raise TimeoutError("Soft timeout reached")
        
        class AlarmContext:
            def __enter__(self_inner):
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(max(int(seconds), 1))
            
            def __exit__(self_inner, exc_type, exc, tb):
                signal.alarm(0)
                signal.signal(signal.SIGALRM, signal.SIG_DFL)
        
        return AlarmContext()
    
    def _find_clean_binary(self, binary_path: str) -> str:
        """Find clean (non-ASAN) version of binary for faster symex."""
        path = Path(binary_path)
        
        # If binary ends with _instrumented, try clean version
        if path.name.endswith('_instrumented'):
            clean_name = path.name.replace('_instrumented', '_clean')
            clean_path = path.parent / clean_name
            if clean_path.exists():
                self.logger.info(f"Found clean binary: {clean_path}")
                return str(clean_path)
        
        return binary_path
    
    def _resolve_avoid_addresses(self, avoid_function_names: List[str]) -> List[int]:
        """Resolve function names to addresses for avoidance."""
        addresses = []
        
        if not avoid_function_names:
            return addresses
        
        try:
            cfg = self.project.analyses.CFGFast()
            
            for func_name in avoid_function_names:
                for func in cfg.functions.values():
                    if func.name == func_name:
                        addresses.append(func.addr)
                        self.logger.debug(f"[SYMEX-AVOID] {func_name} @ {hex(func.addr)}")
                        break
        except Exception as e:
            self.logger.warning(f"Failed to resolve avoid addresses: {e}")
        
        return addresses
