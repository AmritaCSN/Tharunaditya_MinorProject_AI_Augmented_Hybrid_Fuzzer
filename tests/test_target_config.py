from src.analysis.target_config import TargetConfigGenerator
from src.core.interfaces import AnalysisResult, BinaryTarget


def test_semantic_tags_and_filtering():
    generator = TargetConfigGenerator()
    targets = [
        BinaryTarget(name="strcpy_wrapper", address=0x401000, vulnerability_score=9.0, complexity=10, call_depth=2, avoid_functions=[]),
        BinaryTarget(name="_internal_helper", address=0x402000, vulnerability_score=1.0, complexity=2, call_depth=1, avoid_functions=[]),
    ]
    analysis = AnalysisResult(
        binary_path="/bin/test",
        targets=targets,
        total_functions=2,
        high_priority_targets=[],
        metadata={"architecture": "x86_64", "entry_point": "0x401000"},
    )

    config = generator.generate_config(analysis)
    # Internal helper should be filtered out
    assert len(config.targets) == 1
    target_cfg = config.targets[0]
    assert "buffer_overflow" in target_cfg.semantic_tags
    assert target_cfg.name == "strcpy_wrapper"
    assert target_cfg.address == hex(0x401000)
