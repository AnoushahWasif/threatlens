import threading
import time
from collections import deque
from collections.abc import Callable


class HourlyBudget:
    """Caps an action per rolling hour, across the API and per user, so a loop, an abusive
    account or a bug can't run up a bill (LLM drafts) or hammer a free API (scans)."""

    WINDOW = 3_600

    def __init__(
        self, per_hour: int, per_user: int | None = None, now: Callable[[], float] = time.monotonic
    ):
        self.per_hour = per_hour
        self.per_user = per_user
        self._now = now
        self._used: deque[float] = deque()
        self._by_user: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _wait(self, used: deque[float], limit: int, now: float) -> float | None:
        while used and now - used[0] >= self.WINDOW:
            used.popleft()
        return self.WINDOW - (now - used[0]) if len(used) >= limit else None

    def take(self, user_id: str | None = None) -> float | None:
        """Use one. Returns None if allowed, else seconds until the next one frees up."""
        with self._lock:
            return self._take(user_id)

    def _take(self, user_id: str | None) -> float | None:
        now = self._now()
        waits = [self._wait(self._used, self.per_hour, now)]
        mine = None
        if user_id is not None and self.per_user is not None:
            if len(self._by_user) > 10_000:
                # Drop callers with nothing left in the window, so the dict can't grow forever.
                stale = [k for k, v in self._by_user.items() if not v or now - v[-1] >= self.WINDOW]
                for k in stale:
                    del self._by_user[k]
            mine = self._by_user.setdefault(user_id, deque())
            waits.append(self._wait(mine, self.per_user, now))
        blocked = [w for w in waits if w is not None]
        if blocked:
            if mine is not None and not mine:
                del self._by_user[user_id]  # don't keep an empty entry per caller
            return max(blocked)
        self._used.append(now)
        if mine is not None:
            mine.append(now)
        return None
