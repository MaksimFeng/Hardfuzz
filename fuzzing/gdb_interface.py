import os
import signal
import time
import logging as log
import multiprocessing as mp
from typing import Any, NoReturn, Tuple, Dict

from pygdbmi.gdbcontroller import GdbController

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
                response['type'] == 'notify' and
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
                response['type'] == 'notify' and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'reason' in response['payload'] and
                response['payload']['reason'] == 'end-stepping-range'
        ):
            self.stop_responses.put(
                ('step instruction done', response['payload'])
            )
        elif (
                response['type'] == 'notify' and
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
                response['type'] == 'notify' and
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
                response['type'] == 'notify' and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'signal-meaning' in response['payload'] and
                response['payload']['signal-meaning'] == 'Aborted'
        ):
            self.stop_responses.put(('crashed', str(response['payload'])))
        elif (
                response['type'] == 'notify' and
                response['message'] == 'stopped'
        ):
            self.stop_responses.put(('stopped, no reason given', str(response)))
        elif (
                response['type'] == 'target' and
                response['message'] is None and
                'Target halted' in response['payload']
        ):
            pass


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

    def stop(self) -> None:
        log.debug("Stopping GDB...")
        if self.gdb_communicator and self.gdb_communicator.pid:
            os.kill(self.gdb_communicator.pid, signal.SIGUSR1)
            self.gdb_communicator.join(timeout=10)
            exitcode = self.gdb_communicator.exitcode
            if exitcode != 0:
                if self.gdb_communicator.gdbmi and self.gdb_communicator.gdbmi.gdb_process:
                    os.kill(self.gdb_communicator.gdbmi.gdb_process.pid, signal.SIGKILL)
                os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                time.sleep(5)
                raise Exception(f'gdb_manager process exited with {exitcode=}.')
    
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

    def wait_for_stop(self, timeout: float = 5) -> Tuple[str, Any]:
        try:
            msg = self.stop_responses.get(block=True, timeout=timeout)
            log.debug(f"Wait_for_stop received stop event: {msg}")
        except mp.queues.Empty:
            log.debug("Wait_for_stop timed out")
            return ('timed out', None)
        return msg

    def connect(self) -> None:
        log.debug("Connecting to GDB server...")
        self.send('-gdb-set mi-async on')
        self.send('set architecture arm')
        self.send(f'-target-select extended-remote {self.gdb_server_address}')

    def disconnect(self) -> None:
        log.debug("Disconnecting from GDB server...")
        self.send('-target-disconnect')

    def continue_execution(self, retries: int = 3) -> None:
        log.debug("Continuing execution...")
        gdb_response = self.send('-exec-continue --all')
        if gdb_response['message'] == 'error' and retries > 0:
            log.warning(
                f"continue_execution() error: {gdb_response['payload'].get('msg', '')}, retrying..."
            )
            time.sleep(0.5)
            self.continue_execution(retries - 1)

    def interrupt(self) -> None:
        log.debug("Interrupting execution...")
        self.send('-exec-interrupt --all')
        # After interrupt, wait for a stop event
        reason, payload = self.wait_for_stop(timeout=5)
        if reason.startswith('timed out'):
            log.warning("Interrupt timed out, target may not have halted.")
        else:
            log.debug("Target halted after interrupt.")

    def set_breakpoint(self, address_hex_str: str) -> str:
        address = int(address_hex_str, 16)
        log.debug(f"Setting breakpoint at {hex(address)}")
        gdb_response = self.send(f'-break-insert *{hex(address)}')
        if gdb_response['message'] != 'done':
            raise Exception(
                f'Failed to set breakpoint at address {hex(address)}: {gdb_response}'
            )
        bp_id: str = gdb_response['payload']['bkpt']['number']
        log.debug(f"Breakpoint set at {hex(address)}, bkptno={bp_id}")
        return bp_id

    def remove_breakpoint(self, breakpoint_id: str) -> None:
        log.debug(f"Removing breakpoint {breakpoint_id}")
        self.send(f'-break-delete {breakpoint_id}')

    def step_instruction(self) -> None:
        log.debug("Stepping one instruction...")
        response = self.send('-exec-step-instruction')
        if response['message'] == 'error':
            raise Exception(str(response))

    def generate_message_id(self) -> int:
        self.message_id += 1
        return self.message_id