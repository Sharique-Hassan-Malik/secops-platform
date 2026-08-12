import queue
import threading
from pathlib import Path


class LogWatcher:
    """
    Spawns one daemon thread per log source. Each thread tails its file and
    pushes (source_type, line) tuples into a thread-safe queue for the async
    ingestion loop to drain.
    """

    def __init__(self, sources: dict):
        self.queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        for source_type, path in sources.items():
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
            t = threading.Thread(
                target=self._tail,
                args=(source_type, path),
                daemon=True,
                name=f"tail-{source_type}",
            )
            self._threads.append(t)

    def _tail(self, source_type: str, path: Path) -> None:
        with open(path, "r", errors="replace") as fp:
            fp.seek(0, 2)
            while not self._stop.is_set():
                line = fp.readline()
                if line:
                    stripped = line.strip()
                    if stripped:
                        self.queue.put((source_type, stripped))
                else:
                    self._stop.wait(0.1)

    def start(self) -> None:
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
