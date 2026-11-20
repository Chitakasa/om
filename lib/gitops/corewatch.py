#!/usr/bin/env python3
"""`om core watch`: recover a container the moment its process dies unseen (Linux, local engine). The self-heal timer
(`om core heal`, every two minutes) is the fallback everywhere else."""

import os
import subprocess
import time

from gitops.enginectl import _local_engine, _om_pids, revive_zombies
from gitops.omstate import IS_LINUX


class _ContainerWatcher:
    """What `watch` listens to: a pidfd per om container (the kernel says at once when a process exits) and the engine's
    own event stream (it says when the set of containers may have changed)."""

    def __init__(self, runtime: str):
        import select
        self.runtime = runtime
        self.poller = select.poll()
        self.fds: dict[int, str] = {}  # pidfd -> container name
        self.events = self._open_events()
        self.poller.register(self.events.stdout.fileno(), select.POLLIN | select.POLLHUP)
        self._pollin, self._pollhup = select.POLLIN, select.POLLHUP

    def _open_events(self):
        return subprocess.Popen([self.runtime, "events", "--filter", "type=container", "--format", "{{.Status}}"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def refresh(self):
        """Forget every pidfd and open one per running om container."""
        for fd in list(self.fds):
            self.poller.unregister(fd)
            os.close(fd)
        self.fds.clear()
        for pid, name in _om_pids(self.runtime).items():
            try:
                fd = os.pidfd_open(pid)
            except OSError:
                continue  # already gone: revive_zombies handles it
            self.poller.register(fd, self._pollin)
            self.fds[fd] = name

    def wait(self) -> tuple[list[str], bool]:
        """Block up to 60 s: (containers whose process exited, whether the set may have changed)."""
        exited, changed = [], False
        for fd, _ in self.poller.poll(60000) or [(None, 0)]:
            if fd is None:
                changed = True
            elif fd == self.events.stdout.fileno():
                if not self.events.stdout.readline():  # engine event stream ended
                    self.events = self._open_events()
                    self.poller.unregister(fd)
                    self.poller.register(self.events.stdout.fileno(), self._pollin | self._pollhup)
                changed = True
            elif fd in self.fds:
                exited.append(self.fds[fd])
        return exited, changed


def watch(runtime: str, max_events: int | None = None) -> int:
    """Event loop for `om core watch`: recover a container the moment its process dies unseen.

    A pidfd per container tells the kernel-level truth instantly (no polling); the engine's own event
    stream and a 60 s backstop refresh the set. When a process exits, wait 2 s for the engine to record a
    normal exit, then restart whatever it still lists as running (revive_zombies). Linux, local engine only;
    `om core heal` (every 2 min) remains the fallback everywhere else.
    """
    if not (IS_LINUX and hasattr(os, "pidfd_open") and _local_engine(runtime)):
        print("om core watch needs Linux with a local Podman/Docker engine; `om core heal` covers other setups.")
        return 1
    watcher = _ContainerWatcher(runtime)

    def log(msg):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

    watcher.refresh()
    revive_zombies(runtime)
    log(f"watching {len(watcher.fds)} container(s)")
    handled = 0
    while max_events is None or handled < max_events:
        exited, changed = watcher.wait()
        if exited:
            time.sleep(2)
            revived, failed = revive_zombies(runtime)
            if revived or failed:
                log(f"process of {', '.join(exited)} died unseen; restarted {revived or 'nothing'}"
                    + (f", failed {failed}" if failed else ""))
                handled += 1
            changed = True
        if changed:
            watcher.refresh()
    return 0
