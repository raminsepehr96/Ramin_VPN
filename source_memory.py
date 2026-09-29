"""Result memory for Ramin VPN searches.

Remembers, per search kind (a protocol such as "proto:hysteria2", or a country such as
"country:DE"), WHICH source (a T1..Tn Free Vless source, a dedicated protocol feed, FreeProxyDB,
Cloudflare WARP...) delivered a healthy server and which one came back empty.  The next search
of the same kind asks rank() and tries the historically best sources FIRST; sources that never
worked drift to the back but are never excluded, and old results fade out (feeds change daily).

Stored in source_memory.json next to the program.  Everything here is best-effort: a missing or
broken file just means "no memory yet" and never raises.
"""
import json
import os
import threading
import time

_DECAY = 0.92                 # every new result shrinks the older ones a little
_FORGET_AFTER = 30 * 86400    # a result older than this counts for nothing any more
_MAX_SPEED_PENALTY = 0.2      # slow sources rank a bit lower than equally reliable fast ones


class SourceMemory:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def record(self, ns: str, key: str, hit: bool, seconds: float = None) -> None:
        """One search result for source `key` in search kind `ns`."""
        try:
            now = time.time()
            with self._lock:
                bucket = self._data.setdefault(ns, {})
                e = bucket.setdefault(key, {"hits": 0.0, "misses": 0.0, "avg_s": 0.0,
                                            "last_hit": 0, "last_try": 0})
                e["hits"] *= _DECAY
                e["misses"] *= _DECAY
                e["last_try"] = int(now)
                if hit:
                    e["hits"] += 1.0
                    e["last_hit"] = int(now)
                    if seconds is not None:
                        e["avg_s"] = seconds if e["avg_s"] <= 0 else 0.6 * e["avg_s"] + 0.4 * seconds
                else:
                    e["misses"] += 1.0
                self._save()
        except Exception:
            pass

    def score(self, ns: str, key: str) -> float:
        """0..1, higher = try earlier. Unknown sources get a neutral 0.5."""
        with self._lock:
            e = (self._data.get(ns) or {}).get(key)
            if not e:
                return 0.5
            age = time.time() - max(e.get("last_try", 0), 0)
            w = max(0.0, 1.0 - age / _FORGET_AFTER)
            if w <= 0:
                return 0.5
            h, m = e.get("hits", 0.0) * w, e.get("misses", 0.0) * w
            s = (h + 1.0) / (h + m + 2.0)
            if h > 0.3:
                s -= min(e.get("avg_s", 0.0), 120.0) / 120.0 * _MAX_SPEED_PENALTY
            return s

    def rank(self, ns: str, keys: list) -> list:
        """`keys` (in their default order) sorted best-first; ties keep the default order."""
        try:
            scored = [(-self.score(ns, k), i, k) for i, k in enumerate(keys)]
            scored.sort()
            return [k for _s, _i, k in scored]
        except Exception:
            return list(keys)

    def summary(self, ns: str) -> list:
        """[(key, score)] best first - for debugging / README."""
        with self._lock:
            keys = list((self._data.get(ns) or {}).keys())
        return [(k, round(self.score(ns, k), 3)) for k in self.rank(ns, keys)]
