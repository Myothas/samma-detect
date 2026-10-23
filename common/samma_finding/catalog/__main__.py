"""``python3 -m samma_finding.catalog``: print every catalogue as JSON."""

import json
import sys

from . import all_checks, validate

problems = validate()
if problems:
    sys.stderr.write("\n".join(problems) + "\n")
    sys.exit(1)
json.dump(all_checks(), sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
