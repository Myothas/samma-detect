"""The shared ``config.yaml`` loader (environment variables still win)."""

import os
import sys

DEFAULT_CONFIG_PATHS = ("/config.yaml",)


def load(path=None):
    """Return the parsed config, or ``{}`` when the file or PyYAML is absent.

    Lookup order: ``SAMMA_CONFIG``, the ``path`` the scanner passes (its
    ``../../config.yaml``), then ``/config.yaml`` as the images lay it out.
    """
    candidates = []
    env = os.getenv("SAMMA_CONFIG", "").strip()
    if env:
        candidates.append(env)
    if path:
        candidates.append(path)
    candidates.extend(DEFAULT_CONFIG_PATHS)
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        try:
            import yaml  # third-party: PyYAML, installed in every image
        except ImportError:
            sys.stderr.write("WARNING: PyYAML is not installed; using built-in defaults\n")
            return {}
        with open(candidate, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return data if isinstance(data, dict) else {}
    return {}


def section(name, path=None, config=None):
    """The ``name`` section of the config, ``{}`` when missing."""
    data = config if config is not None else load(path)
    value = data.get(name, {})
    return value if isinstance(value, dict) else {}


def truthy(value):
    """The scanners' boolean convention: anything but false/0/no is true."""
    return str(value).strip().lower() not in ("false", "0", "no", "")
