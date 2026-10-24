"""The shared ``config.yaml`` loader and the settings precedence.

Every scanner setting is resolved by :func:`setting`: the environment
variable wins, then the scanner's section of ``config.yaml``, then the
built-in default. Scanners that connect to one port under one scheme use
:func:`endpoint`, which keeps the port tied to the scheme it was written
for (README, "Settings precedence").
"""

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


def env_value(env, name):
    """The variable's value, or ``None`` when it is unset or blank."""
    value = env.get(name)
    if value is None or str(value).strip() == "":
        return None
    return value


def setting(env, section, key, default, env_key=None):
    """One value with the precedence environment > ``config.yaml`` > default.

    ``env_key`` is ``key`` upper-cased unless given. A variable that is set
    but blank counts as unset, and so does a ``config.yaml`` key with a null
    value, so an empty ``PORT=`` in a Job template falls through to the file
    and the built-in default instead of failing to parse.
    """
    value = env_value(env, env_key or key.upper())
    if value is not None:
        return value
    if section.get(key) is not None:
        return section[key]
    return default


def endpoint(env, section, default_https=False):
    """``(https, port)`` for a scanner that connects to one port under one scheme.

    Each value follows the same precedence (environment, then
    ``config.yaml``, then the built-in default) with one rule on top: a port
    only counts together with the scheme it was written for. The file's
    ``port`` is used only when its own ``https`` key, if it has one, names
    the scheme in effect, so a ``port: 80`` written next to ``https: false``
    never pins 80 once ``HTTPS=true`` arrives from the environment. The
    built-in default port follows the scheme: 443 under HTTPS, 80 otherwise.
    """
    https = truthy(setting(env, section, "https", default_https))
    port = env_value(env, "PORT")
    if port is None and section.get("port") is not None:
        file_https = section.get("https")
        if file_https is None or truthy(file_https) == https:
            port = section["port"]
    if port is None:
        port = 443 if https else 80
    return https, int(port)
