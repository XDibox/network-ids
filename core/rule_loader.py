import sys
from pathlib import Path

_RULES_DIR = Path(__file__).parent.parent / 'rules'


def load(rules_dir=None):
    """Load all *.yml files from the rules/ directory.

    Returns a dict keyed by filename stem (e.g. 'port_scan', 'http_attacks').
    Exits with an error message if pyyaml is not installed or the directory is missing.
    """
    try:
        import yaml
    except ImportError:
        print("[ERROR] pyyaml is required. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    d = Path(rules_dir) if rules_dir else _RULES_DIR
    if not d.is_dir():
        print(f"[ERROR] Rules directory not found: {d}", file=sys.stderr)
        sys.exit(1)

    rules = {}
    for path in sorted(d.glob('*.yml')):
        with open(path, encoding='utf-8') as f:
            data = yaml.safe_load(f)
        rules[path.stem] = data

    return rules
