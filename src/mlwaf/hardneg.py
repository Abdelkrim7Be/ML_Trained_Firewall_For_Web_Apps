"""Benign values that look like attacks.

The failures that survived the first corpus rebuild were all of one kind. A search
box accepting `fuel AND vacuum OR space`. A Spanish shop sending `modo=insertar`.
Both contain SQL vocabulary and neither is an attack, and a model that has only
seen SQL words inside attacks has no way to tell.

Vocabulary is not the signal. Structure is. `insertar` is a word; `INSERT INTO`
is a statement. `challenger or 51L` is two search terms; `1' OR 1=1--` closes a
quote, asserts a tautology and comments out the rest of the query. Teaching that
difference needs examples of the first kind, and no corpus of ordinary web traffic
contains enough of them, because they are rare in general and common exactly where
it matters.

So they are generated deliberately. Every value here is harmless and every one is
designed to be mistaken for an attack by something matching on words.
"""

from __future__ import annotations

import random

# Words that contain SQL keywords, or are SQL keywords in ordinary use.
KEYWORD_LOOKALIKES = [
    "selection", "selections", "selected", "preselection", "insertar", "insertion",
    "inserted", "reinsertion", "union", "unions", "unionized", "union square",
    "reunion", "communion", "dropped", "droplet", "dropdown", "raindrop",
    "updates", "updated", "ordering", "order", "reorder", "deleted", "deletion",
    "table", "tables", "tablet", "where", "wherever", "elsewhere", "from",
    "fromage", "having", "behaviour", "grouping", "group", "regrouped",
    "exec", "executive", "execution", "alter", "alteration", "altercation",
    "create", "creative", "creature", "truncate", "declare", "declaration",
    "seleccionar", "actualizar", "ordenar", "borrar", "tabla", "unir",
    "auswahl", "einfugen", "sélection", "insérer", "commande",
]

# Boolean search syntax. A search form that accepts operators is indistinguishable
# from injection by vocabulary alone, and this is the single most common source of
# genuine false positives on real traffic.
SEARCH_TERMS = [
    "orbital elements", "keplerian", "shuttle", "challenger", "apollo", "hubble",
    "fuel", "vacuum", "space", "mpeg", "avi", "documentation", "invoice",
    "annual report", "2024 results", "customer service", "privacy policy",
]
OPERATORS = ["OR", "AND", "or", "and", "NOT", "|", "+"]

# Apostrophes and quotes in ordinary data. A quote is the classic injection
# marker and also appears in a very large number of real surnames.
QUOTED_TEXT = [
    "O'Brien", "D'Angelo", "O'Neill", "d'Artagnan", "l'Hôpital", "N'Diaye",
    "it's fine", "don't stop", "won't fix", "that's all", "rock 'n' roll",
    "the 90's", "he said \"hello\"", "she replied \"no\"", "\"quoted phrase\"",
    "Marks & Spencer", "Smith & Sons", "Ben & Jerry's", "AT&T", "Barnes & Noble",
]

# Angle brackets, arrows and markup-looking text that is not markup.
BRACKET_TEXT = [
    "5 < 10", "a -> b", "x <= y", "1<2 and 3>2", "if x<y then", "temp < 0",
    "<not a tag>", "< back", "next >", "=> result", "a<b<c", "price < 100",
    "2 > 1", "<<< heading >>>", "-->", "<!-- comment -->",
]

# Paths, commands and technical strings that appear in legitimate parameters.
TECHNICAL = [
    "/usr/local/bin", "C:\\Program Files\\App", "../images/logo.png",
    "SELECT * FROM docs -- example in our SQL tutorial",
    "how to prevent sql injection", "xss cheat sheet", "owasp top 10",
    "script.js", "index.php?page=2", "data:image/png;base64,iVBORw0KG",
    "application/json; charset=utf-8", "en-GB,en;q=0.9", "text/html",
    "SELECT", "UPDATE", "DELETE", "sha256:abc123", "v1.2.3-rc1",
    "a=1&b=2", "key=value;other=thing", "2026-01-01T12:00:00Z",
]

# Values in many scripts, so that "not English" cannot mean "attack".
MULTILINGUAL = [
    "Jamón Ibérico", "crème brûlée", "Müller Straße", "naïve café",
    "Añadir al carrito", "Pasar por caja", "Größe wählen", "Prix réduit",
    "Ελληνικά", "Привет мир", "日本語のテキスト", "中文搜索", "한국어",
    "مرحبا بالعالم", "שלום עולם", "ยินดีต้อนรับ", "Türkçe karakterler",
    "Æthelred", "Ångström", "Reykjavík", "Kraków", "Košice", "Timișoara",
]

ORDINARY = [
    "42", "0", "-1", "3.14159", "1e6", "0x1f", "true", "false", "null",
    "user@example.com", "+44 20 7946 0958", "SW1A 1AA", "192.168.1.1",
    "2026-09-11", "09/11/2026", "£19.99", "$1,299.00", "50%", "#hashtag",
    "550e8400-e29b-41d4-a716-446655440000", "AbCdEf123456==",
    "https://example.com/page?ref=home", "mailto:someone@example.com",
]


def generate(count: int, seed: int = 7) -> list[str]:
    """A pool of harmless values chosen to be easy to mistake for attacks."""
    rng = random.Random(seed)
    pool: list[str] = []

    pool += KEYWORD_LOOKALIKES
    pool += QUOTED_TEXT
    pool += BRACKET_TEXT
    pool += TECHNICAL
    pool += MULTILINGUAL
    pool += ORDINARY

    # Boolean search queries, the hardest legitimate case.
    for _ in range(max(count // 4, 200)):
        terms = rng.sample(SEARCH_TERMS, rng.randint(2, 3))
        joined = f" {rng.choice(OPERATORS)} ".join(terms)
        if rng.random() < 0.3:
            joined = f"({terms[0]}) {rng.choice(OPERATORS)} ({terms[-1]})"
        pool.append(joined)

    # Sentences that happen to contain SQL or markup vocabulary.
    for _ in range(max(count // 4, 200)):
        word = rng.choice(KEYWORD_LOOKALIKES)
        template = rng.choice([
            f"how to {word} a record", f"{word} guide for beginners",
            f"our {word} policy", f"the {word} of the year",
            f"{word} and {rng.choice(SEARCH_TERMS)}",
            f"{rng.choice(QUOTED_TEXT)} {word}",
        ])
        pool.append(template)

    # Ordinary text with a stray quote or bracket, which is what real user input
    # looks like once people type freely.
    for _ in range(max(count // 6, 150)):
        base = rng.choice(SEARCH_TERMS + MULTILINGUAL)
        pool.append(rng.choice([f"{base}'", f"'{base}", f"{base}\"", f"<{base}>",
                                f"{base} -- notes", f"{base} #1", f"{base};"]))

    rng.shuffle(pool)
    return pool[:count] if count < len(pool) else pool
