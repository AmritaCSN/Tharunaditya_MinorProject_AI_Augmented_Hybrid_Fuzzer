import pytest
from pathlib import Path
import time
from src.utils.feedback_collector import FeedbackCollector

@pytest.fixture
def afl_output_dir(tmp_path):
    """Create a mock AFL++ output directory structure."""
    output_dir = tmp_path / "afl_out"
    default_dir = output_dir / "default"
    default_dir.mkdir(parents=True)
    return output_dir

def test_get_stats_empty(afl_output_dir):
    """Test getting stats when stats file doesn't exist."""
    collector = FeedbackCollector(str(afl_output_dir))
    stats = collector.get_stats()
    assert stats == {}

def test_get_stats_parsing(afl_output_dir):
    """Test parsing of a valid fuzzer_stats file."""
    stats_file = afl_output_dir / "default" / "fuzzer_stats"
    
    # Mock AFL++ stats content
    content = """
execs_done          : 1000
execs_per_sec       : 100.50
corpus_count        : 50
corpus_found        : 45
saved_crashes       : 2
saved_hangs         : 0
"""
    stats_file.write_text(content)
    
    collector = FeedbackCollector(str(afl_output_dir))
    stats = collector.get_stats(action_taken="FUZZING")
    
    assert stats['execs_done'] == 1000
    assert stats['execs_per_sec'] == 100.50
    assert stats['paths_total'] == 50
    assert stats['crashes_total'] == 2
    assert stats['action_taken'] == "FUZZING"
    assert 'cpu_percent' in stats  # Should be present from psutil

def test_history_tracking(afl_output_dir):
    """Test that history is tracked correctly."""
    stats_file = afl_output_dir / "default" / "fuzzer_stats"
    collector = FeedbackCollector(str(afl_output_dir))
    
    # Snapshot 1
    stats_file.write_text("execs_done : 100\ncorpus_count : 10\nsaved_crashes : 0")
    collector.get_stats()
    
    # Snapshot 2
    stats_file.write_text("execs_done : 200\ncorpus_count : 15\nsaved_crashes : 1")
    collector.get_stats()
    
    assert len(collector.history) == 2
    assert collector.history[0].execs_done == 100
    assert collector.history[1].execs_done == 200
    
    # Check trends
    trends = collector.get_trends(window_size=2)
    assert trends['window_size'] == 2
    assert trends['paths_growth_rate'] > 0
