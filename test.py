from __future__ import annotations
from dataclasses import dataclass
import serial
import time
import json
import random
import logging as log
import os
import _pylibfuzzer
import queue
import signal
import multiprocessing as mp
from typing import Any, NoReturn

from pygdbmi.gdbcontroller import GdbController

log.basicConfig(level=log.DEBUG)  # Set log to DEBUG to see all debug info.

@dataclass
class CorpusEntry:
    content: bytes
    fname: str
    origin: int
    depth: int
    hit_blocks: int = 0
    num_fuzzed: int = 0
    num_childs: int = 0
    weight: float = 1
    burn_in: int = 5

    def compute_weight(self, total_hit_blocks: int, total_corpus_entries: int):
        if self.burn_in:
            self.weight = self.burn_in
        else:
            self.weight = 1.0

    def __str__(self) -> str:
        return (f'{self.fname}, depth={self.depth}, hit_blocks={self.hit_blocks}, '
                f'num_fuzzed={self.num_fuzzed}, childs={self.num_childs}, weight={self.weight}, burn_in={self.burn_in}')

class InputGeneration:
    def __init__(self, output_directory: str, seeds_directory: str | None = None,
                 max_input_length: int = 1024, libfuzzer_so_path: str | None = None):
        if libfuzzer_so_path is None:
            libfuzzer_so_path = os.path.join(
                os.path.dirname(__file__),
                'fuzz_wrappers/libfuzzerSrc/libfuzzer-mutator.so'
            )
            os.environ['libfuzzer_mutator_so_path'] = libfuzzer_so_path

        self.max_input_length = max_input_length
        self.corpus_directory = os.path.join(output_directory, 'corpus')
        os.makedirs(self.corpus_directory, exist_ok=True)

        if seeds_directory is not None and not os.path.exists(seeds_directory):
            raise Exception(f'{seeds_directory=} does not exist.')

        self.corpus: list[CorpusEntry] = []
        self.current_base_input_index: int = -1
        self.retry_corpus_input_index: int = 0
        self.total_hit_blocks = 0

        if seeds_directory:
            self.add_seeds(seeds_directory)

        if len(self.corpus) == 0:
            self.add_corpus_entry(b'{"test":123,"valid":true}', 0, 0)

        _pylibfuzzer.initialize(self.max_input_length)

    def add_seeds(self, seeds_directory: str) -> None:
        for filename in sorted(os.listdir(seeds_directory)):
            filepath = os.path.join(seeds_directory, filename)
            if not os.path.isfile(filepath):
                continue
            with open(filepath, 'rb') as f:
                seed = f.read()
                if len(seed) > self.max_input_length:
                    log.warning(
                        f'Seed {filepath} was not added to the corpus because '
                        f'the seed length ({len(seed)}) was too large {self.max_input_length=}.'
                    )
                    continue
                if seed not in [entry.content for entry in self.corpus]:
                    self.add_corpus_entry(seed, 0, 0)

    def add_corpus_entry(self, input: bytes, address: int, timestamp: int) -> CorpusEntry:
        filepath = os.path.join(
            self.corpus_directory,
            f'id:{str(len(self.corpus))},orig:{self.current_base_input_index},addr:{hex(address)},time:{timestamp}'
        )
        with open(filepath, 'wb') as f:
            f.write(input)

        depth = 0
        if self.current_base_input_index >= 0:
            depth = self.corpus[self.current_base_input_index].depth + 1
            self.corpus[self.current_base_input_index].num_childs += 1

        entry = CorpusEntry(input, filepath, self.current_base_input_index, depth)
        self.corpus.append(entry)
        return entry

    def choose_new_baseline_input(self):
        energy_sum = 0
        cum_energy = []
        for i in self.corpus:
            i.compute_weight(self.total_hit_blocks, len(self.corpus))
            energy_sum += i.weight
            cum_energy.append(energy_sum)
        self.current_base_input_index = random.choices(range(len(cum_energy)), cum_weights=cum_energy).pop()
        chosen_entry = self.corpus[self.current_base_input_index]
        chosen_entry.num_fuzzed += 1
        if chosen_entry.burn_in:
            chosen_entry.burn_in -= 1

    def get_baseline_input(self) -> bytes:
        return self.corpus[self.current_base_input_index].content

    def generate_input(self) -> bytes:
        if self.retry_corpus_input_index < len(self.corpus):
            input_data = self.corpus[self.retry_corpus_input_index].content
            self.retry_corpus_input_index += 1
            return input_data
        generated_inp = _pylibfuzzer.mutate(self.corpus[self.current_base_input_index].content)
        return generated_inp

    def report_address_reached(self, current_input: bytes, address: int, timestamp: int) -> None:
        self.total_hit_blocks += 1
        for i in self.corpus:
            if i.content == current_input:
                i.hit_blocks += 1
                return
        self.retry_corpus_input_index = 0
        entry = self.add_corpus_entry(current_input, address, timestamp)
        entry.hit_blocks += 1
        log.debug(f'New Corpus entry {current_input!r}')


class GDBCommunicator(mp.Process):
    def __init__(
            self,
            stop_responses: mp.Queue[tuple[str, Any]],
            aditional_hit_addresses: mp.Queue[int],
            requests: mp.Queue[str],
            request_responses: mp.Queue[dict[str, Any]],
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


class GDB():
    """Interface to GDB MI API using GDBCommunicator process."""

    def __init__(
            self,
            gdb_path: str = 'gdb-multiarch',
            gdb_server_address: str = 'localhost:2331',
            software_breakpoint_addresses: list[int] = [],
            consider_sw_breakpoint_as_error: bool = False
    ) -> None:
        self.stop_responses: mp.Queue[tuple[str, Any]] = mp.Queue()
        self.aditional_hit_addresses: mp.Queue[int] = mp.Queue()
        self.requests: mp.Queue[str] = mp.Queue()
        self.request_responses: mp.Queue[dict[str, Any]] = mp.Queue()

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

    def send(self, message: str, timeout: int = 10) -> dict[str, Any]:
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
            except queue.Empty:
                raise TimeoutError(
                    f'No response was received for request "{message}" within {timeout} seconds.'
                )
            if response['token'] == message_id:
                log.debug(f"Received matched response for token {message_id}: {response}")
                return response

    def wait_for_stop(self, timeout: float = 5) -> tuple[str, Any]:
        try:
            msg = self.stop_responses.get(block=True, timeout=timeout)
            log.debug(f"Wait_for_stop received stop event: {msg}")
        except queue.Empty:
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


def wait_for_request(ser):
    while True:
        data = ser.read(1)
        if data == b'A':
            return
        time.sleep(0.01)

def process_incoming_data(data):
    if len(data) >= 1:
        response_code = data[0]
        if response_code != 0:
            return data[:1], data[1:]
        else:
            if len(data) >= 5:
                num_bytes = int.from_bytes(data[1:5], byteorder='little')
                total_length = 1 + 4 + num_bytes
                if len(data) >= total_length:
                    remaining_data = data[total_length:]
                    return data[:total_length], remaining_data
    return None, b''

def read_response(ser):
    response = b''
    start_time = time.time()
    timeout = 2
    while True:
        if ser.in_waiting > 0:
            response += ser.read(ser.in_waiting)
            processed_response, remaining_data = process_incoming_data(response)
            if processed_response is not None:
                return processed_response
        if time.time() - start_time > timeout:
            break
        time.sleep(0.01)
    return response

def process_response(response):
    if not response:
        log.warning("No response from the board.")
        return
    response_code = response[0]
    if response_code != 0:
        error_code = response_code
        log.error(f"Received error code: {error_code}")
    else:
        num_bytes = int.from_bytes(response[1:5], byteorder='little')
        if len(response) < 5 + num_bytes:
            log.error("Incomplete response data.")
            log.debug(f"Response: {response.hex()}")
            return
        data_to_decode = response[5:5+num_bytes]
        try:
            json_data = data_to_decode.decode('utf-8')
            log.info(f"Received JSON data ({num_bytes} bytes): {json_data}")
        except UnicodeDecodeError as e:
            log.error(f"UnicodeDecodeError: {e}")
            log.debug(f"Data to decode (hex): {data_to_decode.hex()}")

def send_test_case(ser, test_case_bytes):
    wait_for_request(ser)
    data_length = len(test_case_bytes)
    ser.write(data_length.to_bytes(4, byteorder='little'))
    ser.write(test_case_bytes)
    log.info(f"Sent {data_length} bytes of data.")
    log.info(f"Data: {test_case_bytes}")
    response = read_response(ser)
    return response

def parse_def_use_file(filename='def_use1.txt'):
    def_dict = {}
    with open(filename, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]

    i = 0
    while i < len(lines):
        if lines[i].startswith("Definition:"):
            def_line = lines[i]
            use_line = lines[i+1] if i+1 < len(lines) and lines[i+1].startswith("Use:") else None
            if use_line:
                def_addr_str = def_line.split()[-1]
                use_addr_str = use_line.split()[-1]
                if def_addr_str not in def_dict:
                    def_dict[def_addr_str] = []
                def_dict[def_addr_str].append(use_addr_str)
                i += 2
            else:
                i += 1
        else:
            i += 1

    sorted_defs = sorted(def_dict.items(), key=lambda x: len(x[1]), reverse=True)
    return sorted_defs
def halt_target(gdb: GDB, max_retries=3):
    """Interrupt the target and wait until it's stopped, ensuring we can change breakpoints."""
    for attempt in range(max_retries):
        log.debug("Halting target before changing breakpoints...")
        gdb.interrupt()
        reason, payload = gdb.wait_for_stop(timeout=5)
        if reason == 'timed out':
            log.warning("Halt attempt timed out, retrying...")
        else:
            log.debug(f"Target halted with reason: {reason}")
            return  # Successfully halted
    raise Exception("Could not halt the target after multiple attempts.")

def set_breakpoints_for_defs(gdb: GDB, defs_group):
    # Ensure the target is halted before deleting/adding breakpoints
    halt_target(gdb)
    log.debug("Deleting all existing breakpoints...")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        raise Exception(f"Failed to delete breakpoints while halted: {resp['payload'].get('msg', '')}")
    log.info("Deleted all breakpoints.")

    defs_map = {}
    for i, (def_addr, uses) in enumerate(defs_group[:3]):
        # Target is halted, safe to insert breakpoints
        bkptno = gdb.set_breakpoint(def_addr)
        if bkptno is not None:
            defs_map[bkptno] = (def_addr, uses)
    return defs_map

def set_breakpoints_for_uses(gdb: GDB, uses):
    # Halt before adding uses breakpoints
    halt_target(gdb)
    uses_map = {}
    for use_addr in uses[:3]:
        # Target halted, safe to insert breakpoints
        bkptno = gdb.set_breakpoint(use_addr)
        if bkptno is not None:
            uses_map[bkptno] = use_addr
    return uses_map

def main(use_watchpoints=False):
    no_trigger_threshold = 2
    test_case_count_since_last_trigger = 0
    current_group_index = 0

    gdb = GDB(
        gdb_path='gdb-multiarch',
        gdb_server_address='localhost:2331',
        software_breakpoint_addresses=[],
        consider_sw_breakpoint_as_error=False
    )

    log.debug("Starting GDB setup...")
    gdb.connect()

    # Reset and halt the target so GDB knows where we are.
    log.debug("Resetting and halting the target...")
    gdb.send('monitor reset halt')

    # Load the ELF and symbols
    elf_path = '/home/kai/project/Hardfuzz/example/consule/sketch_nov5a.ino.elf'
    log.debug(f"Loading ELF: {elf_path}")
    gdb.send(f'-file-exec-and-symbols {elf_path}')
    # No 'load' if firmware already on board

    # Insert breakpoint at main
    log.debug("Inserting breakpoint at main...")
    gdb.send('-break-insert main')

    # Run the program and wait for main breakpoint
    log.debug("Running the program...")
    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        log.warning("Could not run the program. Attempting to continue instead...")
        gdb.continue_execution()

    # Wait for a stop event at main
    reason, payload = gdb.wait_for_stop(timeout=10)
    if reason == 'timed out':
        log.warning("No stop event (e.g., main breakpoint hit) after running. Trying to halt manually.")
        halt_target(gdb)  # If we didn't hit main, just halt the target now.

    sorted_defs = parse_def_use_file('def_use1.txt')
    defs_in_groups = [sorted_defs[i:i+3] for i in range(0, len(sorted_defs), 3)]
    if not defs_in_groups:
        log.error("No definitions found in def_use file.")
        return

    # Now that target is halted (hit main or manually halted), set initial breakpoints
    defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
    mode = 'breakpoint'

    ser = serial.Serial('/dev/ttyACM0', 38400, timeout=1)
    time.sleep(2)

    output_directory = 'output'
    seeds_directory = 'seeds'
    input_gen = InputGeneration(
        output_directory=output_directory,
        seeds_directory=seeds_directory,
    )

    try:
        while True:
            input_gen.choose_new_baseline_input()
            test_case_bytes = input_gen.generate_input()

            try:
                test_case_str = test_case_bytes.decode('utf-8')
            except UnicodeDecodeError:
                log.debug("Failed to decode input as UTF-8, skipping.")
                continue

            log.info(f"Sending test case: {test_case_str}")
            response = send_test_case(ser, test_case_bytes)
            process_response(response)
            log.info("Continuing execution and waiting for events...")
            gdb.continue_execution()

            reason, payload = gdb.wait_for_stop(timeout=5)
            event_happened = False

            if reason == 'breakpoint hit':
                event_happened = True
                test_case_count_since_last_trigger = 0
                bkptno = payload
                if bkptno in defs_map:
                    def_addr, uses = defs_map[bkptno]
                    print(f"{mode.capitalize()} triggered at def {def_addr}, setting breakpoints at its uses.")
                    uses_map = set_breakpoints_for_uses(gdb, uses)
                    gdb.continue_execution()

                    # Wait again for hits on uses
                    reason2, payload2 = gdb.wait_for_stop(timeout=5)
                    if reason2 == 'breakpoint hit':
                        print(f"Breakpoint at use {payload2} hit.")
                        gdb.continue_execution()
                else:
                    print(f"Breakpoint hit at {payload}")
                    gdb.continue_execution()

            elif reason == 'timed out':
                log.info("No events triggered by this test case.")
                test_case_count_since_last_trigger += 1
                if test_case_count_since_last_trigger > no_trigger_threshold:
                    current_group_index += 1
                    if current_group_index < len(defs_in_groups):
                        # Halt target before resetting breakpoints
                        defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
                        test_case_count_since_last_trigger = 0
                    else:
                        log.info("No more definition groups to try.")

            timestamp = int(time.time())
            input_gen.report_address_reached(test_case_bytes, address=0, timestamp=timestamp)

            time.sleep(0.1)

    except KeyboardInterrupt:
        log.info("Stopping fuzzing.")
    finally:
        ser.close()
        gdb.stop()

if __name__ == '__main__':
    main()
