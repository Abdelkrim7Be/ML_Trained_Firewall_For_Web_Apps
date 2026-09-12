"""Decompose a request into the pieces that can actually carry an attack.

Scoring a whole request forces the model to answer the wrong question. A request
is mostly context: the path, the parameter names, the other values sitting beside
the payload. None of that is the attack, but all of it varies from site to site,
so the model learns what a particular site's traffic looks like and calls anything
unfamiliar an attack. That is why a model trained on NASA's static file traffic
flags a quarter of a Spanish shop's checkout requests, including
`modo=agregar&precio=8456`, which contains no attack syntax at all.

An injection lives in one value. So the unit of decision is one value:

    GET /tienda1/pagar.jsp?modo=insertar&precio=8456&B1=Pasar+por+caja

    -> path   /tienda1/pagar.jsp
    -> modo   insertar
    -> precio 8456
    -> B1     Pasar por caja

Each is scored on its own and the request takes the worst. Three consequences
follow, and all three are the point:

1. Context cannot leak. `precio=8456` is scored without knowing that the site is
   Spanish, or that the path says `tienda1`.
2. Dilution stops working. Padding a query with two hundred junk parameters used
   to drop an attack's score below the threshold; now each parameter is scored
   alone and the junk is simply two hundred more benign units.
3. The training corpus stops being arbitrary. A benign unit is any real parameter
   value from any site; an attack unit is any payload. Neither needs a plausible
   request built around it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from mlwaf.decode import decode, request_parts

# A body larger than this is not parsed into units; it is scored as one blob.
MAX_UNIT_CHARS = 4096
# ~1.5ms/unit; paired with WAF_SCORING_BUDGET_MS in waf/config.py to bound
# worst-case latency. Units beyond the cap are not scored.
MAX_UNITS = 64


@dataclass(frozen=True)
class Unit:
    kind: str      # "path", "query", "body", "blob"
    name: str      # parameter name, empty for path and blob
    value: str     # the raw value, before normalisation

    def text(self) -> str:
        """What the model sees.

        The parameter name is deliberately left out. It is site vocabulary, the
        same class of thing as the path, and including it reintroduces exactly the
        leak this decomposition exists to close.
        """
        decoded, _ = decode(self.value)
        canonical, _, _ = request_parts("", "", decoded, "")
        return canonical

    def depth(self) -> int:
        return decode(self.value)[1]


def _pairs(blob: str) -> list[tuple[str, str]]:
    """Form encoded, JSON, or a single opaque value."""
    stripped = blob.strip()
    if stripped.startswith(("{", "[")):
        try:
            return list(_walk_json(json.loads(stripped)))
        except (json.JSONDecodeError, RecursionError):
            pass
    if "=" in blob:
        return parse_qsl(blob, keep_blank_values=True)
    return [("", blob)]


def _walk_json(node, prefix: str = ""):
    """Every leaf of a JSON body is a value an attacker can reach."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk_json(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _walk_json(value, f"{prefix}[{i}]")
    elif node is not None and not isinstance(node, bool):
        yield prefix, str(node)


def decompose(method: str, path: str, query: str, body: str) -> list[Unit]:
    units: list[Unit] = []

    if path and path not in ("/", ""):
        # The path is one unit: traversal and command injection live here, and it
        # is short enough that scoring it whole costs nothing.
        units.append(Unit("path", "", path))

    for source, kind in ((query, "query"), (body, "body")):
        if not source:
            continue
        if len(source) > MAX_UNIT_CHARS:
            units.append(Unit("blob", "", source[:MAX_UNIT_CHARS]))
            continue
        for name, value in _pairs(source):
            if value:
                units.append(Unit(kind, name, value[:MAX_UNIT_CHARS]))

    if not units:
        units.append(Unit("path", "", path or "/"))
    return units[:MAX_UNITS]
