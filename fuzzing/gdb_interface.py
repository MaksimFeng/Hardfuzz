import os
import signal
import time, socket
import logging as log
import multiprocessing as mp
from typing import Any, NoReturn, Tuple, Dict

from pygdbmi.gdbcontroller import GdbController
logger = log.getLogger(__name__)
#optional import the config setting
from config.settings import (
    LOG_LEVEL, LOG_FORMAT, SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
    OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
    NO_TRIGGER_THRESHOLD
)

class GDBCommunicator(mp.Process):
    def __init__(
            self,
            stop_responses: mp.Queue,  # Contains Tuple[str, Any]
            aditional_hit_addresses: mp.Queue,  # Contains int
            requests: mp.Queue,  # Contains str
            request_responses: mp.Queue,  # Contains Dict[str, Any]
            software_breakpoint_addresses: list[int],
            consider_sw_breakpoint_as_error: bool,
            gdb_path: str
    ) -> None:
        super().__init__()
        self.software_breakpoint_addresses = software_breakpoint_addresses
        self.consider_sw_breakpoint_as_error = consider_sw_breakpoint_as_error
        self.stop_responses = stop_responses
        self.aditional_hit_addresses = aditional_hit_addresses
        self.requests = requests
        self.request_responses = request_responses
        self.gdbmi = GdbController(
            gdb_path.split() + ["--nx", "--quiet", "--interpreter=mi3"]
        )
        self.running = True
        self.console_messages: list[dict[str, Any]] = []

    def run(self) -> NoReturn:
        signal.signal(signal.SIGUSR1, self.on_exit)
        while self.running:
            while not self.requests.empty():
                request = self.requests.get(block=False)
                log.debug(f"Sending GDB command: {request}")
                self.console_messages = []
                self.gdbmi.write(request, read_response=False, timeout_sec=0)

            try:
                responses = self.gdbmi.get_gdb_response(
                    timeout_sec=0,
                    raise_error_on_timeout=False
                )
            except Exception as e:
                log.error(f'Exception from get_gdb_response: {e}')
                raise e

            for response in responses:
                log.debug(f'Received GDB response: {response}')
                if 'token' in response and response['token'] is not None:
                    response['console_data'] = self.console_messages
                    self.console_messages = []
                    self.request_responses.put(response)
                elif 'type' in response and response['type'] == 'console':
                    self.console_messages.append(response)
                else:
                    self.on_stop_response(response)

    def on_exit(self, signum: Any, frame: Any) -> None:
        self.running = False
        self.gdbmi.exit()
        process = self.gdbmi.gdb_process
        if process:
            try:
                process.terminate()
                process.communicate(timeout=5)
            except TimeoutError as e:
                log.warning(f"Timeout error on stopping GDB: {e}")
                os.kill(process.pid, signal.SIGKILL)

    def on_stop_response(self, response: dict[str, Any]) -> None:
        # Handle stop events
        if (
                response['type'] == ('notify','exec') and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'reason' in response['payload'] and
                response['payload']['reason'] == 'breakpoint-hit' and
                'bkptno' in response['payload']
        ):
            self.stop_responses.put(
                ('breakpoint hit', response['payload']['bkptno'])
            )
        elif (
                response['type'] == ('notify','exec') and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'reason' in response['payload'] and
                response['payload']['reason'] == 'end-stepping-range'
        ):
            self.stop_responses.put(
                ('step instruction done', response['payload'])
            )
        elif (
                response['type'] == ('notify','exec') and
                response['message'] == 'thread-group-exited'
        ):
            self.stop_responses.put(('exited', ''))
        elif (
                response['type'] == 'log' and
                isinstance(response['payload'], str) and
                response['payload'].startswith('Remote communication error')
        ):
            self.stop_responses.put(('communication error', response['payload']))
        elif (
                response['type'] == ('notify','exec') and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'signal-meaning' in response['payload'] and
                response['payload']['signal-meaning'] in
                ['Interrupt', 'Trace/breakpoint trap', 'Signal 0']
        ):
            pc = int(response['payload']['frame']['addr'], 16)
            if pc in self.software_breakpoint_addresses or self.consider_sw_breakpoint_as_error:
                self.stop_responses.put(('crashed', str(response['payload'])))
            else:
                self.stop_responses.put(
                    ('interrupt', pc)
                )
        elif (
                response['type'] == ('notify','exec') and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'signal-meaning' in response['payload'] and
                response['payload']['signal-meaning'] == 'Aborted'
        ):
            self.stop_responses.put(('crashed', str(response['payload'])))
        elif (
                response['type'] == ('notify','exec') and
                response['message'] == 'stopped'
        ):
            self.stop_responses.put(('stopped, no reason given', str(response)))
        elif (
                response['type'] == 'target' and
                response['message'] is None and
                'Target halted' in response['payload']
        ):
            payload = response['payload'].split(', ')
            for chunk in payload:
                key_val = chunk.split('=')
                if key_val[0] == 'pc':
                    self.aditional_hit_addresses.put(int(key_val[1], 16))
                    logger.warning(f"Additional hit address: {key_val[1]}")


class GDB:
    """Interface to GDB MI API using GDBCommunicator process."""

    def __init__(
            self,
            gdb_path: str = 'gdb-multiarch',
            gdb_server_address: str = 'localhost:2331',
            software_breakpoint_addresses: list[int] = [],
            consider_sw_breakpoint_as_error: bool = False
    ) -> None:
        self.stop_responses: mp.Queue = mp.Queue()
        self.aditional_hit_addresses: mp.Queue = mp.Queue()
        self.requests: mp.Queue = mp.Queue()
        self.request_responses: mp.Queue = mp.Queue()

        self.gdb_communicator = GDBCommunicator(
            self.stop_responses,
            self.aditional_hit_addresses,
            self.requests,
            self.request_responses,
            software_breakpoint_addresses,
            consider_sw_breakpoint_as_error,
            gdb_path
        )
        self.gdb_communicator.daemon = True
        self.gdb_communicator.start()

        self.gdb_server_address = gdb_server_address
        self.message_id: int = 0

    def stop_discard(self) -> None:
        log.debug("Stopping GDB...")
        if self.gdb_communicator and self.gdb_communicator.pid:
            os.kill(self.gdb_communicator.pid, signal.SIGUSR1)
            self.gdb_communicator.join(timeout=10)
            exitcode = self.gdb_communicator.exitcode
            if exitcode is None:
                log.warning("GDB did not exit after SIGUSR1, sending SIGKILL")
                try: 
                    os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.gdb_communicator.join(timeout=5)
                exitcode = self.gdb_communicator.exitcode
            if exitcode is None:
                log.error("GDB is still alive after SIGKILL, something is wrong.")
            
            if exitcode != 0:
                if self.gdb_communicator.gdbmi and self.gdb_communicator.gdbmi.gdb_process:
                    os.kill(self.gdb_communicator.gdbmi.gdb_process.pid, signal.SIGKILL)
                os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                time.sleep(5)
                raise Exception(f'gdb_manager process exited with {exitcode=}.')
    def stop(self) -> None:
        log.debug("Stopping GDB...")

        try:
            # Attempt a graceful disconnect
            self.send('-target-disconnect', timeout=3)
        except Exception as e:
            log.debug(f"No target to disconnect or ignoring error: {e}")

        if self.gdb_communicator and self.gdb_communicator.pid:
            log.debug("Sending SIGUSR1 to GDBCommunicator...")
            os.kill(self.gdb_communicator.pid, signal.SIGUSR1)

            self.gdb_communicator.join(timeout=10)
            exitcode = self.gdb_communicator.exitcode

            # If still alive => force-kill
            if exitcode is None:
                log.warning("GDBCommunicator did not exit after SIGUSR1, sending SIGKILL.")
                try:
                    os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Probably it died in the meantime

                self.gdb_communicator.join(timeout=5)
                exitcode = self.gdb_communicator.exitcode

            if exitcode is None:
                log.error("GDBCommunicator is still alive after SIGKILL. Something is wrong.")

            # If the communicator has a nonzero exit code, also kill raw gdb
            if exitcode not in (0, None):
                log.error(f"GDBCommunicator exited with code {exitcode}, killing raw gdb.")

                # Kill the real gdb process
                if self.gdb_communicator.gdbmi and self.gdb_communicator.gdbmi.gdb_process:
                    try:
                        os.kill(self.gdb_communicator.gdbmi.gdb_process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

                # Only call os.kill() on the communicator again if exitcode != -9
                # i.e., we haven't already SIGKILL'd it and reaped it
                if exitcode != -9:
                    try:
                        os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

                time.sleep(1)
                # raise Exception(f"GDBCommunicator process exited with {exitcode=}.")
        else:
            log.debug("No active GDBCommunicator to stop.")


    
    def send(self, message: str, timeout: int = 10) -> Dict[str, Any]:
        message_id = self.generate_message_id()
        log.debug(f"Queueing GDB command: {message} with token {message_id}")
        message = str(message_id) + message
        self.requests.put(message)
        timeout_time = time.time() + timeout
        while True:
            timeout_seconds_left = timeout_time - time.time()
            try:
                response = self.request_responses.get(
                    block=True,
                    timeout=timeout_seconds_left
                )
            except mp.queues.Empty:
                raise TimeoutError(
                    f'No response was received for request "{message}" within {timeout} seconds.'
                )
            if response['token'] == message_id:
                log.debug(f"Received matched response for token {message_id}: {response}")
                return response

    def wait_for_stop(self, timeout: float = 360000) -> Tuple[str, Any]:
        try:
            msg = self.stop_responses.get(block=True, timeout=timeout)
            log.debug(f"Wait_for_stop received stop event: {msg}")
        except mp.queues.Empty:
            log.debug("Wait_for_stop timed out")
            return ('timed out', None)
        return msg

    def connect(self, path) -> None:
        log.debug("Connecting to GDB server...")
        self.send('-gdb-set mi-async on')
        self.send('set architecture arm')
        elf_path = ELF_PATH
        self.send(f'file {path}')
        self.send(f'-target-select extended-remote {self.gdb_server_address}')

    def connect_qemu(
        self,
        elf_path: str,
        *,
        architecture: str | None = None,
        remote_first: bool = False,
        max_tries: int = 8,
        delay: float = 0.5,
        gdb_server_address: str = 'localhost:2331'
    ) -> None:
        """Robustly attach to a live qemu-stub (already listening)."""
        self.send('-gdb-set mi-async on')
        # if architecture:
        #     self.send(f'set architecture {architecture}')

        # wait until port is reachable
        import socket, time
        host, port = gdb_server_address.split(":")
        port = int(port)
        end = time.time() + max_tries * delay
        # while time.time() < end:
        #     with socket.socket() as s:
        #         s.settimeout(0.2)
        #         if s.connect_ex((host, port)) == 0:
        #             # s.sendall(b'$D#44') 
        #             # s.close() 
        #             try:
        #                 s.sendall(b'$D#44')
        #             except OSError:
        #                 pass
        #             break
        #     time.sleep(delay)
        # else:
        #     raise TimeoutError(f"GDB port {self.gdb_server_address} not open")

        # now MI attach
        if remote_first:
            self.send(f'-target-select extended-remote {gdb_server_address}')
            self.send(f'-file-exec-and-symbols {elf_path}')
        else:
            self.send(f'-file-exec-and-symbols {elf_path}')
            self.send(f'-target-select extended-remote {gdb_server_address}')
    def disconnect(self) -> None:
        log.debug("Disconnecting from GDB server...")
        self.send('-target-disconnect')

    def continue_execution(self, retries: int = 3) -> None:
        log.debug("Continuing execution...")
        # only change this part. 
        # self.send('monitor reset')
        # self.send('monitor halt')
        gdb_response = self.send('-exec-continue --all')
        if gdb_response['message'] == 'error' and retries > 0:
            log.warning(
                f"continue_execution() error: {gdb_response['payload'].get('msg', '')}, Trying continue_execution() again in 0.5 seconds"
            )
            time.sleep(0.5)
            self.continue_execution(retries - 1)

#why do I want to interrupt?
    def interrupt_ignore(self, gdb) -> 'GDB | None':
        log.debug("Interrupting execution...")
        self.send('-exec-interrupt --all')
        self.send('monitor halt')
        self.send('monitor reset')
        reason, payload = self.wait_for_stop(timeout=5)
        if reason.startswith('timed out'):
            log.warning("Interrupt timed out, target may not have halted.")
            # Try again
            self.send('-exec-interrupt --all')
            reason, _ = self.wait_for_stop(timeout=5)
            if reason.startswith('timed out'):
                log.error("Second interrupt also timed out.")
                # Possibly do a heavier reset or kill GDB
                new_gdb = self.kill_and_reinit_gdb(ELF_PATH)
                return new_gdb  # <-- Return the new GDB object
                # return None
            else:
                return gdb
        else:
            log.debug(f"Target halted after interrupt (reason={reason}).")

        # Then do the monitor commands
            self.send('monitor halt')
            self.send('monitor reset')
            return gdb
    def interrupt(self) -> 'GDB | None':
        """
        Attempt to interrupt the target. If we fail twice, kill and reinit GDB.
        Return a new GDB instance if we had to kill/reinit, otherwise None.
        """
        log.debug("Interrupting execution...")
        self.send('-exec-interrupt --all')

        # Wait up to 5s for a stop event
        reason, payload = self.wait_for_stop(timeout=5)
        if reason.startswith('timed out'):
            log.warning("Interrupt timed out, target may not have halted.")
            # Try again
            self.send('-exec-interrupt --all')
            reason, _ = self.wait_for_stop(timeout=5)
            if reason.startswith('timed out'):
                log.error("Second interrupt also timed out. Killing/Reinit GDB.")
                new_gdb = self.kill_and_reinit_gdb(ELF_PATH)
                if not new_gdb.gdb_communicator.is_alive():
                    log.error("New GDB died immediately")
                time.sleep(1)  # Give it a moment to settle
                return new_gdb  # Return the brand-new GDB instance
            else:
                log.debug(f"Target halted on second try => reason={reason}.")
        else:
            log.debug(f"Target halted after interrupt => reason={reason}.")

        # If we get here, we have a halted CPU and didn't kill GDB
        # We can do extra commands if we want, but typically you'd do them in the caller
        return None

    def kill_and_reinit_gdb(old_gdb, elf_path, server_address='localhost:2331'):
        """
        Kill old GDB, wait, create new GDB, connect, do reset/halt, load symbols, etc.
        """
        logger.warning("Killing existing GDB process ...")
        old_gdb.stop()

        # Wait up to 5 seconds for old communicator to vanish
        end_time = time.time() + 5
        while old_gdb.gdb_communicator.is_alive() and time.time() < end_time:
            time.sleep(0.2)

        if old_gdb.gdb_communicator.is_alive():
            logger.error("Old GDBCommunicator is still alive after forced kill. Proceeding anyway.")

        time.sleep(0.5)  # let OS reap

        logger.info("Starting fresh GDB instance ...")
        from .gdb_interface import GDB
        new_gdb = GDB(
            gdb_path='gdb-multiarch',
            gdb_server_address=server_address,
            software_breakpoint_addresses=[],
            consider_sw_breakpoint_as_error=False
        )

        # Reconnect & setup
        new_gdb.connect(elf_path)
        new_gdb.send(f'-target-select extended-remote {server_address}')
        new_gdb.send('monitor halt')
        new_gdb.send('monitor reset')
        

        new_gdb.send(f'-file-exec-and-symbols {elf_path}')
        new_gdb.send('-break-insert main')
        reason, payload = new_gdb.wait_for_stop(timeout=10)
        logger.info(f"New GDB init => reason={reason}, payload={payload}")
        if reason in ("breakpoint hit", "stopped, no reason given"):
            logger.debug("Main breakpoint reached. Good to go.")
        else:
            logger.warning("Target did not hit main as expected => continuing anyway.")
            new_gdb.continue_execution()

        return new_gdb

    # def interrupt(self) -> 'GDB | None':
    #     """
    #     Attempt to interrupt the target. If we fail twice, kill and reinit GDB.
    #     Return a new GDB instance if we had to kill/reinit, otherwise None.
    #     """
    #     log.debug("Interrupting execution...")
    #     self.send('-exec-interrupt --all')

    #     # Wait up to 5s for a stop event
    #     reason, payload = self.wait_for_stop(timeout=5)
    #     if reason.startswith('timed out'):
    #         log.warning("Interrupt timed out -> fall back to monitor halt.")
    #         # log.warning("Interrupt timed out, target may not have halted.")
    #         # Try again
    #         self.send('monitor halt')
    #         # self.send('-exec-interrupt --all')
    #         reason, _ = self.wait_for_stop(timeout=5)
    #         if reason.startswith('timed out'):
    #             log.error("Still running → kill & re-init GDB.")
    #             new_gdb = self.kill_and_reinit_gdb(ELF_PATH)
    #             if not new_gdb.gdb_communicator.is_alive():
    #                 log.error("New GDB died immediately")
    #             time.sleep(1)  # Give it a moment to settle
    #             return new_gdb  # Return the brand-new GDB instance
    #         else:
    #             log.debug(f"Target halted on second try => reason={reason}.")
    #     else:
    #         log.debug(f"Target halted after interrupt => reason={reason}.")

    #     # If we get here, we have a halted CPU and didn't kill GDB
    #     # We can do extra commands if we want, but typically we'd do them in the caller
    #     return None

    # def kill_and_reinit_gdb(old_gdb, elf_path, server_address='localhost:2331'):
    #     """
    #     Kill old GDB, wait, create new GDB, connect, do reset/halt, load symbols, etc.
    #     """
    #     logger.warning("Killing existing GDB process ...")
    #     old_gdb.stop()
    #     time.sleep(0.5)
    #     from .gdb_interface import GDB  # import here to avoid circular import
    #     new_gdb = GDB(gdb_path='gdb-multiarch', gdb_server_address=server_address)
    #     new_gdb.connect(elf_path)
    #     new_gdb.send(f'-target-select extended-remote {server_address}')
    #     new_gdb.send('monitor halt')
    #     new_gdb.send(f'-file-exec-and-symbols {elf_path}')
    #     new_gdb.send('-break-insert main')
    #     new_gdb.continue_execution()
    #     # new_gdb.wait_for_stop(timeout=10)
    #     reason, payload = new_gdb.wait_for_stop(timeout=10)
    #     logger.info(f"New GDB init => reason={reason}, payload={payload}")
    #     return new_gdb   
    # def interrupt(self) -> None:
    #     log.debug("Interrupting execution...")
    #     self.send('-exec-interrupt --all')
    #     self.send('monitor reset')
    #     self.send('monitor halt')
    #     # self.send('-exec-interrupt --all')
    #     # mayber there are some bugs here
    #     # After interrupt, wait for a stop event
    #     reason, payload = self.wait_for_stop(timeout=5)
    #     if reason.startswith('timed out'):
    #         log.warning("Interrupt timed out, target may not have halted.")
    #     else:
    #         log.debug("Target halted after interrupt.")


        
        # self.send('-exec-interrupt --all')
        # mayber there are some bugs here
        # After interrupt, wait for a stop event
        # reason, payload = self.wait_for_stop(timeout=5)
        # if reason.startswith('timed out'):
        #     log.warning("Interrupt timed out, target may not have halted.")
        # else:
        #     log.debug("Target halted after interrupt.")
    def force_interrupt_or_kill_ignore(self, timeout = 5) -> bool:
        """
        Tries '-exec-interrupt --all', waits for a stop event up to 'timeout'.
        If still not stopped, kills GDB process. Returns True if halted.
        """
        self.send('-exec-interrupt --all')
        self.send('monitor halt')
        self.send('monitor reset')
        reason, payload = self.wait_for_stop(timeout=timeout)
        if reason.startswith('timed out'):
            log.warning("Interrupt timed out. Killing GDB process.")
            self.stop()  # triggers GDBCommunicator on_exit() => but might not do anything if gdb is unresponsive
            # Optionally SIGKILL if it is still alive:
            if self.gdb_communicator and self.gdb_communicator.pid:
                try:
                    os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                except OSError as e:
                    log.warning(f"Could not SIGKILL GDB process: {e}")
            return False
        else:
            log.debug(f"Target halted after interrupt (reason={reason}).")
            return True

    def kill_and_reinit_gdb_test(old_gdb, elf_path, server_address='localhost:2331'):
        """
        Completely kills the old GDB instance (including the underlying gdb process),
        waits until it is definitely gone, then creates a fresh GDB instance and
        reconnects to the remote target (e.g., J-Link on localhost:2331).
        """
        logger.warning("Killing existing GDB process ...")
        old_gdb.stop()

        # Wait up to 5 seconds for the old communicator to vanish
        end_time = time.time() + 5
        while old_gdb.gdb_communicator.is_alive() and time.time() < end_time:
            time.sleep(0.2)
        if old_gdb.gdb_communicator.is_alive():
            logger.error("Old GDBCommunicator is still alive after forced kill. Proceeding anyway...")

        # Optional: A short extra sleep to let OS clean up any child processes
        time.sleep(0.5)

        logger.info("Starting fresh GDB instance ...")
        from .gdb_interface import GDB  # import here to avoid circular import
        new_gdb = GDB(
            gdb_path='gdb-multiarch',   
            gdb_server_address=server_address,
            software_breakpoint_addresses=[],
            consider_sw_breakpoint_as_error=False
        )

        # Reconnect and do initial setup
        new_gdb.connect(elf_path)

        # For a J-Link or other remote target, explicitly select the remote:
        # (If your GDB class doesn't do this internally, do it here.)
        new_gdb.send(f'-target-select extended-remote {server_address}')

        # Typical reset/halt for an ARM board via J-Link
        new_gdb.send('monitor reset')
        new_gdb.send('monitor halt')

        # Load symbols and set a main breakpoint
        new_gdb.send(f'-file-exec-and-symbols {elf_path}')
        new_gdb.send('-break-insert main')
        # run_resp = new_gdb.send('-exec-run')
        # if run_resp['message'] == 'error':
        #     logger.warning("Could not run after reinit; attempting a manual continue.")
            # new_gdb.continue_execution()
        if not new_gdb.gdb_communicator.is_alive():
            logger.error("in stopNew GDBCommunicator is not alive after reinit. Something went wrong.")
        # Wait to see if we hit main or some stop
        reason, payload = new_gdb.wait_for_stop(timeout=10)
        logger.info(f"New GDB init => reason={reason}, payload={payload}")
        if reason in ("breakpoint hit", "stopped, no reason given"):
            logger.debug("Main breakpoint reached. Good to go.")
        else:
            logger.warning("Target did not hit main as expected; continuing anyway.")
            new_gdb.continue_execution()

        return new_gdb




    def kill_and_reinit_gdb_discord(old_gdb, elf_path, server_address='localhost:2331'):
        """
        Completely kills the old GDB (if it's still alive), then creates a fresh 
        GDB instance, loads the ELF, does a monitor reset/halt, etc.
        
        :param old_gdb: The existing GDB instance to kill.
        :param elf_path: Path to the ELF file used for debugging.
        :param server_address: GDB server address (localhost:2331, etc.)
        :return: a new GDB instance (freshly started).
        """
        logger.warning("Killing existing GDB process ...")
        old_gdb.stop()  # This calls gdb_communicator.on_exit (SIGUSR1) from your existing code
        # I've done this in the stop function
        # If stop() doesn't fully terminate, do a SIGKILL:
        # if old_gdb.gdb_communicator and old_gdb.gdb_communicator.pid:
        #     try:
        #         os.kill(old_gdb.gdb_communicator.pid, signal.SIGKILL)
        #     except ProcessLookupError:
        #         logger.debug("Old GDB communicator already gone.")
        #     except Exception as e:
        #         logger.warning(f"Could not SIGKILL old GDB process: {e}")
        end_time = time.time() + 5

        while old_gdb.gdb_communicator.is_alive() and time.time() < end_time:
            time.sleep(0.2)

        # If it's still alive after 5s, log an error but continue anyway
        if old_gdb.gdb_communicator.is_alive():
            logger.error("Old GDBCommunicator is still alive even after SIGKILL. Proceeding anyway.")

        # A small extra delay so the OS can fully reap child processes
        time.sleep(0.5)
        # Wait a bit for the old process to vanish
        time.sleep(1)
        
        # Now create a brand-new GDB instance using your constructor
        logger.info("Starting fresh GDB instance ...")
        from .gdb_interface import GDB  # import here to avoid circular import
        new_gdb = GDB(
            gdb_path='gdb-multiarch',   
            gdb_server_address=server_address,
            software_breakpoint_addresses=[],
            consider_sw_breakpoint_as_error=False
        )
        
        # Reconnect and do initial setup:
        new_gdb.connect(elf_path)
        new_gdb.send('monitor reset')
        new_gdb.send('monitor halt')
        
        # Load symbols and set a main breakpoint, if desired
        new_gdb.send(f'-file-exec-and-symbols {elf_path}')
        new_gdb.send('-break-insert main')
        run_resp = new_gdb.send('-exec-run')
        if run_resp['message'] == 'error':
            logger.warning("Could not run after reinit; continuing.")
            new_gdb.continue_execution()

        # Optionally wait for main to be hit
        reason, payload = new_gdb.wait_for_stop(timeout=10)
        logger.info(f"New GDB init => reason={reason}, payload={payload}")
        if reason in ("breakpoint hit", "stopped, no reason given"):
            logger.debug("Main breakpoint reached. Good to go.")
        else:
            logger.warning("Target did not hit main as expected; continuing anyway.")
            new_gdb.continue_execution()

        return new_gdb
    
    def set_breakpoint(self, address_hex_str: str, hw: bool= False) -> str:
        # address = int(address_hex_str, 16)
        address = int(address_hex_str, 16) & ~1
        log.info(f"Setting breakpoint at {hex(address)}")
        gdb_response = self.send(f'-break-insert *{hex(address)}')
        # flag = '-h' if hw else ''
        # gdb_response = self.send(f'-break-insert {flag} *{hex(address)}')
        if gdb_response['message'] != 'done':
            raise Exception(
                f'Failed to set breakpoint at address {hex(address)}: {gdb_response}'
            )
        bp_id: str = gdb_response['payload']['bkpt']['number']
        log.info(f"Breakpoint set at {hex(address)}, bkptno={bp_id}")
        return bp_id

    def remove_breakpoint(self, breakpoint_id: str) -> None:
        log.debug(f"Removing breakpoint {breakpoint_id}")
        self.send(f'-break-delete {breakpoint_id}')

    def step_instruction(self) -> None:
        log.debug("Stepping one instruction...")
        response = self.send('-exec-step-instruction')
        if response['message'] == 'error':
            raise Exception(str(response))
        
    def restart_program(self, elf_path: str) -> None:
        """
        Restart the program from scratch:
        1. monitor reset halt
        2. -file-exec-and-symbols elf_path
        3. -break-insert main
        4. -exec-run
        5. Wait for stop at main
        """
        logger.debug("Restarting program from scratch...")
        # Reset and halt
        # resp = self.send('monitor reset halt')
        resp = self.send('monitor reset')
        resp = self.send('monitor halt')
        if resp['message'] == 'error':
            raise Exception(f"Failed to reset halt the target: {resp['payload'].get('msg','')}")

        # Load symbols
        resp = self.send(f'-file-exec-and-symbols {elf_path}')
        if resp['message'] == 'error':
            raise Exception(f"Failed to load symbols: {resp['payload'].get('msg','')}")

        # Insert breakpoint at main
        resp = self.send('-break-insert main')
        if resp['message'] == 'error':
            raise Exception(f"Failed to set breakpoint at main: {resp['payload'].get('msg','')}")

        # Run the program
        run_resp = self.send('-exec-run')
        if run_resp['message'] == 'error':
            logger.warning("Could not run the program. Attempting to continue instead...")
            self.continue_execution()

        # Wait for stop at main
        reason, payload = self.wait_for_stop(timeout=10)
        if reason == 'timed out':
            raise Exception("Program did not halt at main after restart.")
        logger.debug(f"Program restarted and halted at main or known stop. Reason: {reason}")

    def generate_message_id(self) -> int:
        self.message_id += 1
        return self.message_id
