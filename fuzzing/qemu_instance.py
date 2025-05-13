from __future__ import annotations

import atexit
import logging as log
import subprocess
import time
from pathlib import Path
from typing import Any, List
import os
from fuzzing.gdb_qemu import GDB_QEMU

__all__ = ["QEMUInstance"]

class QEMUInstance:

    def __init__(
        self,
        *,
        elf_path: str,
        qemu_path: str = "qemu-x86_64",
        gdb_path: str = "gdb-multiarch",
        gdb_port: int = 2331,               
        # extra_qemu_args: List[str] | None = None,
        qemu_args: List[str] | None = None,
        target_args: List[str] | None = None,
        stderr_dir: str | None = None,
        pause_at_entry: bool = True,
    ) -> None:
        self.elf_path = Path(elf_path).resolve(strict=True)
        self._gdb_port = gdb_port

  
        # gflag = f"{self._gdb_port},suspend=y" if pause_at_entry else str(self._gdb_port)
        gflag = f"{self._gdb_port},suspend=y" if pause_at_entry else str(self._gdb_port)
        coverage_plugin_path = os.path.join(os.path.dirname(__file__), '../../qemu_new_11_05/qemu-plugins/libbbtrace.so')
        qemu_cmd = [qemu_path,"-plugin", coverage_plugin_path, "-d", "plugin", "-g", gflag,  *(qemu_args or []), self.elf_path.as_posix(), *(target_args or [])]

        log.info("Launching QEMU: %s", " ".join(qemu_cmd))
        stderr_target: Any
        if stderr_dir:
            Path(stderr_dir).mkdir(parents=True, exist_ok=True)
            stderr_target = open(Path(stderr_dir, "qemu_stderr.log"), "ab", 0)
        else:
            stderr_target = subprocess.DEVNULL
        # stderr_target = open(Path(stderr_dir, "qemu_stderr.log"), "ab", 0)
        stdout_target = open(Path(stderr_dir, "target_stdout.log"), "ab", 0)
        self._qemu_proc = subprocess.Popen(
            qemu_cmd,
            stdin=subprocess.PIPE,       # let the fuzzer feed stdin later
            # stdout=subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=stderr_target,
        )

        time.sleep(0.5)
        if self._qemu_proc.poll() is not None:
            raise RuntimeError("QEMU exited immediately – check qemu_stderr.log")

  
        self.gdb = GDB_QEMU(
            qemu_process=self._qemu_proc,
            gdb_path=gdb_path,
            gdb_server_address=f"localhost:{self._gdb_port}",
            software_breakpoint_addresses=[],
        )

        self.gdb.connect_qemu(
            self.elf_path.as_posix(),
            architecture="i386:x86-64",   # architecture of *host* CPU
            remote_first=True,
        )

        # Ensure the guest is stopped; if not, interrupt once.
        # reason, _ = self.gdb.wait_for_stop(timeout=5)
        # if reason.startswith("timed out"):
        #     log.debug("Initial stop timed out – sending interrupt …")
        #     self.gdb.interrupt()
        #     reason, _ = self.gdb.wait_for_stop(timeout=5)
        # assert not reason.startswith("timed out"), "initial stop failed again"
        # log.debug("GDB connected and target halted (%s).", reason)

        atexit.register(self.stop)

    # ───────────────────────────── housekeeping ───────────────────────────────

    def stop(self) -> None:
        if getattr(self, "_qemu_proc", None):
            self._qemu_proc.kill(); self._qemu_proc.wait(5)
            self._qemu_proc = None
        if getattr(self, "gdb", None):
            self.gdb.stop()


    @property
    def process(self) -> subprocess.Popen[Any]:  # noqa: D401
        return self._qemu_proc
