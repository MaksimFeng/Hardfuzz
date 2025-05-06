from __future__ import annotations
import signal
from typing import Any

from fuzzing.gdb_interface import GDB
import logging as log
#similary to gdbfuzz

class GDB_QEMU(GDB):

    def __init__(
        self,
        qemu_process: Any,
        gdb_path: str,
        gdb_server_address: str,
        software_breakpoint_addresses: list[int] | None = None,
    ) -> None:
        super().__init__(
            gdb_path=gdb_path,
            gdb_server_address=gdb_server_address,
            software_breakpoint_addresses=software_breakpoint_addresses or [],
            consider_sw_breakpoint_as_error=False,
        )
        self.qemu_process = qemu_process


    def interrupt(self):  
        
        exit_code = self.qemu_process.poll()
        if exit_code is not None:
            raise RuntimeError(f"QEMU crashed (exit={exit_code}).")
        log.debug("Sending host SIGINT to QEMU …")
  
        self.qemu_process.send_signal(signal.SIGINT)
        return super().interrupt()

    def set_breakpoint(self, address_hex_str: str, hw: bool = False) -> str:
        return super().set_breakpoint(address_hex_str, hw=False)
