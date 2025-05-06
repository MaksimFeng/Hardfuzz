import contextlib
import socket
import subprocess
import time
import signal
import logging as log
import multiprocessing as mp
from pygdbmi.gdbcontroller import GdbController
from fuzzing.gdb_interface import GDB
from typing import Any, List
from fuzzing.gdb_qemu import GDB_QEMU
import atexit

# log.basicConfig(level=log.DEBUG,
                    # format="%(levelname)s:%(name)s:%(message)s")

def get_free_tcp_port() -> int:
    with contextlib.closing(socket.socket()) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

class GdbSession:
    def __init__(self, qemu_path="qemu-x86_64-static",
                       guest_elf:str="/usr/bin/objdump",
                       prefix="/",
                       extra_qemu_args: List[str]|None=None):
        self.log = log.getLogger(__name__)
        self._gdb_port = get_free_tcp_port()
  
        self.qemu_path = qemu_path
        self.bin_path = guest_elf
        self.prefix = prefix
        self.qemu_args = extra_qemu_args or []
    def _spawn_qemu(self, qemu_path, elf, prefix, extra):
        cmd = [qemu_path, "-g", str(self._gdb_port), elf]
        log.info("QEMU cmd: %s", " ".join(cmd))
        return subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    def init_qemu(self, bin_path: str, path_to_qemu: str, output_dir: str):
        self.bin_path = bin_path
        self.path_to_qemu = path_to_qemu
        atexit.register(self.stop)

        # 启动 QEMU
        self.qemu_process = self.start(output_dir)
        
    def start(self, output_dir):
        # same flags here:
        qemu_cmd = [self.path_to_qemu, "-g", str(self._gdb_port), self.bin_path] + self.qemu_args   
        log.info("Starting QEMU: %s", " ".join(qemu_cmd))
        log.info("Waiting for stub on tcp://localhost:%d …", self._gdb_port)
        p = subprocess.Popen(
            qemu_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)
        if (code := p.poll()) is not None:
            out, err = p.communicate(timeout=1)
            log.error("QEMU stdout:\n%s", out.decode(errors="ignore"))
            log.error("QEMU stderr:\n%s", err.decode(errors="ignore"))
            raise RuntimeError(f"QEMU died {code}")
        return p
    def init_gdb(self, gdb_path="gdb-multiarch") -> GDB_QEMU:
        log.info("Spawning GDB wrapper, will attach to tcp://localhost:%d", self._gdb_port)
        gdb = GDB_QEMU(
            qemu_process=self.qemu_process,
            gdb_path=gdb_path,
            gdb_server_address=f"localhost:{self._gdb_port}",
            software_breakpoint_addresses=[],
        )
        log.info("GDB connected, waiting for initial stop …")
        gdb.connect_qemu(self.bin_path, architecture="i386:x86-64", remote_first=True, gdb_server_address=f"localhost:{self._gdb_port}")
        # gdb.send("-break-insert main")
        gdb.send("-break-insert main")

        reason, info = gdb.wait_for_stop(timeout=30)
        assert reason == "stopped, no reason given", f"{reason=}, {info=}"
        return gdb

    def stop(self) -> None:
        atexit.unregister(self.stop)
        if self.qemu_process:
            self.qemu_process.kill()
            self.qemu_process.wait(timeout=5)
            self.qemu_process = None




if __name__ == "__main__":
    log.basicConfig(level=log.DEBUG, format="%(levelname)s: %(message)s")
    sess = GdbSession(
    qemu_path="/home/kai/project/hello",
    guest_elf="/usr/bin/objdump",
    prefix="/",
    # extra_qemu_args=["-x", "-"] 
    # extra_qemu_args=["-D"],
)

    sess.init_qemu(
        bin_path="/home/kai/project/hello",
        path_to_qemu="qemu-x86_64-static",
        output_dir="/output",
    )
    sess.qemu_args = ["-x", "-"] 

    # gdb = sess.init_gdb(gdb_path="gdb-multiarch")

    gdb = sess.init_gdb()

    sess.stop()
