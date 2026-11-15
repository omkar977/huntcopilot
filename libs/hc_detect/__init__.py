"""HuntCopilot detection engine (owner: M2)."""
from .engine import evaluate, evaluate_rules, prepare_events
from .loader import Rule, RuleLoadError, load_rule_file, load_rules, parse_rule

__all__ = [
    "Rule",
    "RuleLoadError",
    "evaluate",
    "evaluate_rules",
    "load_rule_file",
    "load_rules",
    "parse_rule",
    "prepare_events",
]
__version__ = "1.0.0"
