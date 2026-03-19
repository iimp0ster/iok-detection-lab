#!/usr/bin/env python3
"""
UAPool — rotating user-agent pool.

Provides realistic browser UA strings drawn from a curated list of common
Chrome and Firefox versions.  Used by BatchEngine to vary the UA per scan.
"""

import random
import threading


# Curated pool of modern desktop UAs.  Update periodically.
_DEFAULT_POOL = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

# Short labels for history display (keyed by substring match)
_UA_LABELS = {
    "Firefox": "FF",
    "Edg/":    "Edge",
    "Chrome":  "Chr",
}


def _label(ua: str) -> str:
    for key, short in _UA_LABELS.items():
        if key in ua:
            return short
    return "Unk"


def get_random_ua() -> str:
    """Return a randomly selected UA string from the default pool."""
    return random.choice(_DEFAULT_POOL)


class UAPool:
    """
    Thread-safe pool of user-agent strings.

    Parameters
    ----------
    pool : list[str] | None
        Custom UA list.  Defaults to :data:`_DEFAULT_POOL`.
    strategy : str
        ``"random"`` (default) — pick a random UA each time.
        ``"sequential"`` — cycle through pool in order.
    """

    def __init__(self, pool=None, strategy: str = "random"):
        self._pool = list(pool or _DEFAULT_POOL)
        self._strategy = strategy
        self._index = 0
        self._lock = threading.Lock()

    def get(self) -> str:
        """Return a user-agent string."""
        with self._lock:
            if self._strategy == "sequential":
                ua = self._pool[self._index % len(self._pool)]
                self._index += 1
                return ua
            return random.choice(self._pool)

    def label(self, ua: str = None) -> str:
        """Return a short display label for a UA string."""
        return _label(ua or self.get())

    def __len__(self) -> int:
        return len(self._pool)
