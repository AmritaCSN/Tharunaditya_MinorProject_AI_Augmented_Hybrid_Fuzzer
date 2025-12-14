"""
AI-Enhanced Seed Generator
Generates diverse seed corpus for fuzzing campaigns
"""

import logging
import random
import string
from typing import List, Dict, Any, Set
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class SeedGenerationSummary:
    """Summary of seed generation process."""
    total_seeds: int
    seeds_by_strategy: Dict[str, int]
    seeds_by_hint: Dict[str, int]
    output_directory: str
    total_size_bytes: int
    unique_patterns: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_seeds': self.total_seeds,
            'seeds_by_strategy': self.seeds_by_strategy,
            'seeds_by_hint': self.seeds_by_hint,
            'output_directory': self.output_directory,
            'total_size_bytes': self.total_size_bytes,
            'unique_patterns': self.unique_patterns
        }


class AISeedGenerator:
    """
    Generate diverse seed corpus for fuzzing.
    
    Features:
    - Multiple generation strategies
    - Format string payloads
    - Buffer boundary values
    - Special characters and encodings
    - Hint-based generation
    """
    
    # Generation strategies
    STRATEGIES = [
        'random_ascii',
        'random_binary',
        'format_strings',
        'buffer_boundaries',
        'special_chars',
        'repeated_patterns',
        'gradient_lengths',
        'mixed_content'
    ]
    
    # Format string payloads
    FORMAT_STRINGS = [
        '%s%s%s%s%s',
        '%x%x%x%x%x',
        '%n%n%n%n%n',
        '%s%n%x%p%d',
        '%.100000x',
        '%p%p%p%p',
        '%hn%hn%hn',
        '%%%s%%%s%%%s'
    ]
    
    # Buffer boundary sizes
    BUFFER_SIZES = [
        8, 16, 32, 64, 128, 256, 512, 1024,
        2048, 4096, 8192, 16384
    ]
    
    # Special characters
    SPECIAL_CHARS = [
        '\x00',  # Null byte
        '\xff',  # 255
        '\x90',  # NOP sled
        '\n', '\r', '\t',  # Whitespace
        '"', "'", '`',  # Quotes
        '\\', '/', '|',  # Separators
        '$', '&', ';',  # Shell metacharacters
        '<', '>',  # Redirects
        '{', '}', '[', ']',  # Brackets
    ]
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize seed generator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Extract config
        seed_config = config.get('seed_generation', {})
        self.num_seeds = seed_config.get('num_seeds', 100)
        self.max_seed_size = seed_config.get('max_size', 4096)
        self.strategies = seed_config.get('strategies', self.STRATEGIES)
        
        # Track generated patterns
        self.generated_patterns: Set[bytes] = set()
    
    def generate_seeds(self, output_dir: str, hints: List[str] = None, force_clean: bool = False) -> SeedGenerationSummary:
        """
        Generate seed corpus.
        
        Args:
            output_dir: Directory to write seeds
            hints: Generation hints from target config
            force_clean: Whether to clean output directory before generation
            
        Returns:
            SeedGenerationSummary with statistics
        """
        self.logger.info(f"Generating {self.num_seeds} seeds to {output_dir}")
        
        # Create output directory
        output_path = Path(output_dir)
        
        if force_clean and output_path.exists():
            import shutil
            try:
                shutil.rmtree(output_path)
                self.logger.info(f"Cleaned existing seed directory: {output_dir}")
            except Exception as e:
                self.logger.warning(f"Failed to clean seed directory: {e}")
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        hints = hints or []
        seeds_by_strategy = {}
        seeds_by_hint = {}
        total_size = 0
        seed_count = 0
        
        # Distribute seeds across strategies
        seeds_per_strategy = self.num_seeds // len(self.strategies)
        
        for strategy in self.strategies:
            self.logger.debug(f"Generating {seeds_per_strategy} seeds with strategy: {strategy}")
            strategy_count = 0
            
            for i in range(seeds_per_strategy):
                # Generate seed
                seed_data = self._generate_by_strategy(strategy, hints)
                
                # Skip duplicates
                if seed_data in self.generated_patterns:
                    continue
                
                self.generated_patterns.add(seed_data)
                
                # Write to file
                seed_file = output_path / f"seed_{seed_count:05d}_{strategy}.txt"
                with open(seed_file, 'wb') as f:
                    f.write(seed_data)
                
                total_size += len(seed_data)
                strategy_count += 1
                seed_count += 1
            
            seeds_by_strategy[strategy] = strategy_count
        
        # Generate hint-based seeds
        for hint in hints:
            hint_count = 0
            for i in range(10):  # 10 seeds per hint
                seed_data = self._generate_by_hint(hint)
                
                if seed_data in self.generated_patterns:
                    continue
                
                self.generated_patterns.add(seed_data)
                
                seed_file = output_path / f"seed_{seed_count:05d}_{hint}.txt"
                with open(seed_file, 'wb') as f:
                    f.write(seed_data)
                
                total_size += len(seed_data)
                hint_count += 1
                seed_count += 1
            
            seeds_by_hint[hint] = hint_count
        
        summary = SeedGenerationSummary(
            total_seeds=seed_count,
            seeds_by_strategy=seeds_by_strategy,
            seeds_by_hint=seeds_by_hint,
            output_directory=output_dir,
            total_size_bytes=total_size,
            unique_patterns=len(self.generated_patterns)
        )
        
        self.logger.info(f"Generated {seed_count} unique seeds ({total_size} bytes)")
        return summary
    
    def _generate_by_strategy(self, strategy: str, hints: List[str]) -> bytes:
        """Generate seed using specific strategy."""
        if strategy == 'random_ascii':
            return self._random_ascii()
        elif strategy == 'random_binary':
            return self._random_binary()
        elif strategy == 'format_strings':
            return self._format_strings()
        elif strategy == 'buffer_boundaries':
            return self._buffer_boundaries()
        elif strategy == 'special_chars':
            return self._special_chars()
        elif strategy == 'repeated_patterns':
            return self._repeated_patterns()
        elif strategy == 'gradient_lengths':
            return self._gradient_lengths()
        elif strategy == 'mixed_content':
            return self._mixed_content()
        else:
            return self._random_ascii()
    
    def _generate_by_hint(self, hint: str) -> bytes:
        """Generate seed based on hint."""
        if 'format_specifiers' in hint:
            return self._format_strings()
        elif 'long_strings' in hint:
            size = random.choice([512, 1024, 2048, 4096])
            return b'A' * size
        elif 'boundary_values' in hint:
            return self._buffer_boundaries()
        elif 'shell_metacharacters' in hint:
            metacharacters = ['|', '&', ';', '\n', '$(', '`', '\x00']
            return ''.join(random.choices(metacharacters, k=20)).encode('utf-8', errors='ignore')
        elif 'integer_boundaries' in hint:
            values = ['0', '-1', '2147483647', '-2147483648', '4294967295']
            return random.choice(values).encode('utf-8')
        else:
            return self._random_ascii()
    
    def _random_ascii(self) -> bytes:
        """Generate random ASCII string."""
        length = random.randint(1, min(256, self.max_seed_size))
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choices(chars, k=length)).encode('utf-8')
    
    def _random_binary(self) -> bytes:
        """Generate random binary data."""
        length = random.randint(1, min(256, self.max_seed_size))
        return bytes([random.randint(0, 255) for _ in range(length)])
    
    def _format_strings(self) -> bytes:
        """Generate format string payloads."""
        payload = random.choice(self.FORMAT_STRINGS)
        # Add some padding
        padding = 'A' * random.randint(0, 100)
        return (padding + payload).encode('utf-8')
    
    def _buffer_boundaries(self) -> bytes:
        """Generate seeds at buffer boundaries."""
        size = random.choice(self.BUFFER_SIZES)
        # Generate at, before, and after boundary
        offset = random.choice([-1, 0, 1])
        actual_size = max(1, size + offset)
        return b'B' * actual_size
    
    def _special_chars(self) -> bytes:
        """Generate seeds with special characters."""
        length = random.randint(10, 100)
        chars = []
        for _ in range(length):
            if random.random() < 0.3:  # 30% special chars
                chars.append(random.choice(self.SPECIAL_CHARS))
            else:
                chars.append(random.choice(string.ascii_letters))
        return ''.join(chars).encode('utf-8', errors='ignore')
    
    def _repeated_patterns(self) -> bytes:
        """Generate repeated pattern seeds."""
        patterns = [b'A', b'AB', b'ABC', b'ABCD', b'\x90', b'\x00']
        pattern = random.choice(patterns)
        repeat_count = random.randint(10, 200)
        return pattern * repeat_count
    
    def _gradient_lengths(self) -> bytes:
        """Generate seeds with gradient lengths."""
        # Start with small, grow incrementally
        base_char = random.choice(['A', 'B', 'X'])
        length = random.choice([8, 16, 32, 64, 128, 256, 512])
        return base_char.encode('utf-8') * length
    
    def _mixed_content(self) -> bytes:
        """Generate seeds with mixed content types."""
        parts = []
        
        # Add ASCII part
        parts.append(self._random_ascii())
        
        # Add format string
        if random.random() < 0.3:
            parts.append(random.choice(self.FORMAT_STRINGS).encode('utf-8'))
        
        # Add special chars
        if random.random() < 0.5:
            special = ''.join(random.choices(self.SPECIAL_CHARS, k=5))
            parts.append(special.encode('utf-8', errors='ignore'))
        
        # Add boundary test
        if random.random() < 0.4:
            size = random.choice([64, 128, 256])
            parts.append(b'C' * size)
        
        return b''.join(parts)
    
    def save_summary(self, summary: SeedGenerationSummary, output_file: str) -> None:
        """Save generation summary to JSON."""
        import json
        
        with open(output_file, 'w') as f:
            json.dump(summary.to_dict(), f, indent=2)
        
        self.logger.info(f"Saved seed summary to {output_file}")
