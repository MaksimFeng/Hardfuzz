import os
import time
import random
import logging
import logging.handlers
import re
import configparser
import multiprocessing as mp

#change the breakpoint to hardware breakpoint

from fuzzing.coverage_manager import CoverageManager
from config.settings import (
    LOG_LEVEL, LOG_FORMAT, LOG_DATEFMT, LOG_FILE,
    SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
    OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
    NO_TRIGGER_THRESHOLD
)
from fuzzing.gdb_interface import GDB
# from fuzzing.gdb_interface
from fuzzing.input_generation import InputGeneration
from utils.file_parsing import parse_def_use_file
from utils.file_parsing import parse_external
from utils.file_parsing import parse_block
from utils.file_parsing import parse_block_with_full_details

from communication.serial_comm import SerialConnection

HW_BREAKPOINT_LIMIT = 6
MAX_DEF_TRIES_PER_CHUNK = 1
MAX_USE_TRIES = 1
NUM_ROUNDS = 999999
global_hit_counts = {}

def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(LOG_LEVEL)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)
    ch = logging.StreamHandler()
    ch.setLevel(LOG_LEVEL)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=5
    )
    fh.setLevel(LOG_LEVEL)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger

logger = setup_logging()

def increment_bp_hit_count(d_str):
    global_hit_counts[d_str] = global_hit_counts.get(d_str, 0) + 1

def convert_parsed_to_blocklist(parsed_data: dict) -> list[tuple[str, list[str]]]:
    flattened = []
    for block_addr, defs_uses_in_block in parsed_data.items():
        # dicts like:
        # {
        #   "def_addr": "0x1008",
        #   "use_addrs": ["0x1010", "0x1014"],
        #   "use_block_addrs": ["0x1010", "0x1014"]
        # }
        combined_use_blocks = []

        for entry in defs_uses_in_block:
            flitered = [
                x for x in entry["use_block_addrs"]
                if x.lower() not in ("(none)", "(not in cfg)")
            ]
            combined_use_blocks.extend(flitered)

        combined_use_blocks = sorted(set(combined_use_blocks))

        flattened.append((block_addr, combined_use_blocks))

    return flattened

def get_defs_in_weighted_random_order(all_defs):
    
    weighted_list = []
    local_usage_count = {}
    for d_str, u_list in all_defs:
        base_w = max(1, len(u_list))
        weighted_list.append((d_str, u_list, base_w))
        local_usage_count[d_str] = 0

    while weighted_list:
        total_weight = 0.0
        new_list = []
        for (d_str, u_list, base_w) in weighted_list:
            loc_hit = local_usage_count[d_str]
            glob_hits = global_hit_counts.get(d_str, 0)
            scale = (1.0 / (1 + loc_hit)) * (1.0 / (1 + glob_hits) ** 0.5)
            w = base_w * scale
            new_list.append((d_str, u_list, w))
            total_weight += w

        r = random.random() * total_weight
        cumulative = 0.0
        for i, (d, u, w) in enumerate(weighted_list):
            cumulative += w
            if cumulative >= r:
                yield (d, u)
                local_usage_count[d] += 1
                break

def get_closest_uses(def_addr_str, uses_list):
    def_addr = int(def_addr_str, 16)
    return sorted(uses_list, key=lambda u: abs(int(u, 16) - def_addr))

def force_halt_if_running_test(gdb: GDB, max_attempts=5, wait_timeout=5) -> GDB:
    # same code as original
    for attempt in range(max_attempts):
        # this part can be deleted
        logger.info(f"Attempting to force halt CPU, attempt {attempt + 1} of {max_attempts}.")
        resp = gdb.send('-data-list-register-values x', timeout=3)
        if resp['message'] == 'done':
            logger.info("CPU is halted.")
            return gdb
        else:
            logger.info(f"CPU not halted => attempt={attempt+1}, sending interrupt.")
            maybe_new_gdb = gdb.interrupt(gdb)
            if maybe_new_gdb is not None:
                gdb = maybe_new_gdb
                logger.info("GDB re-initialized after interrupt.")
            while True:
                reason, payload = gdb.wait_for_stop(timeout=wait_timeout)
                if reason == 'timed out':
                    break
                if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
                    break
            return gdb
    # raise Exception("Could not force CPU to halt after multiple attempts.")
def force_halt_if_running(gdb: GDB, max_attempts=5, wait_timeout=10) -> GDB:
    """
    Attempt up to max_attempts times to confirm the CPU is halted 
    by reading registers. If not halted, do an interrupt. If that fails 
    twice in interrupt(), we reinit GDB. If we do reinit, we reassign gdb.
    """
    for attempt in range(max_attempts):
        logger.info(f"Attempting to force halt CPU, attempt {attempt + 1} of {max_attempts}.")
        # gdb.send('monitor halt')
        gdb.send('-exec-interrupt --all')
        gdb.send('monitor reset')
        resp = gdb.send('-data-list-register-values x', timeout=3)
        if resp['message'] == 'done':
            logger.info("CPU is halted.")
            return gdb
        else:
            logger.info(f"CPU not halted => sending interrupt (attempt {attempt+1}).")
            maybe_new_gdb = gdb.interrupt()
            if maybe_new_gdb is not None:
                gdb = maybe_new_gdb
                logger.info("GDB re-initialized after interrupt.")

            # Now let's see if we actually got a stop event. We'll do a short loop:
            reason, payload = gdb.wait_for_stop(timeout=wait_timeout)
            if reason.startswith('timed out'):
                logger.warning("After interrupt, still no stop => keep looping.")
                # We'll keep going in the for-loop => next attempt
            else:
                if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
                    logger.info(f"Stopped => reason={reason}. We'll check regs again on next loop.")
                # No break => we do the next attempt anyway

    logger.error("Could not force CPU to halt after multiple attempts. Returning anyway.")
    return gdb
def _really_hatled(gdb:GDB) -> bool:
    """helper: check if the CPU is halted"""
    resp = gdb.send('-data-list-register-values x', timeout=3)
    return resp['message'] == 'done'
# def force_halt_if_running(gdb: GDB, max_attempts:int=5, wait_timeout:int=5) -> GDB:
#     """
#     Robustly stop the core **without resetting it**.
#     A loop of:
#     1) read regs → if 'done' → halted
#     2) ^C interrupt + wait
#     3) monitor halt + wait
#     after each step we *verify* with `_really_halted()`.
#     """
#     for attempt in range(max_attempts):
#         # gdb.send('')
#         if _really_hatled(gdb):
#             return gdb;
#         maybe_new = gdb.interrupt()
#         if maybe_new:
#             gdb = maybe_new
#         gdb.wait_for_stop(timeout=wait_timeout)
#         if _really_hatled(gdb):
#             return gdb
        
#         # interrupt didn't succeed->try jlink hard halt
#         gdb.send('monitor halt')
#         gdb.send('monitor reset')
#         gdb.wait_for_stop(timeout=wait_timeout)
#         if _really_hatled(gdb):
#             return gdb
#     logger.error("Could not halt CPU -> giving up")
#     # inside force_halt_if_running() after the loop
#     if not _really_hatled(gdb):
#         return GDB.kill_and_reinit_gdb(gdb, ELF_PATH)
#     return gdb


# kill process but problem occure
# def force_halt_if_running(gdb: GDB, max_attempts=3, wait_timeout=5):
#     """
#     Tries to confirm the CPU is halted by reading registers. If not halted,
#     we call interrupt() and wait_for_stop() repeatedly. If everything fails,
#     we kill GDB and re-init.
    
#     Returns a (bool, GDB) tuple: 
#         (True, same_gdb) if it was able to halt without reinit
#         (True, new_gdb)  if it had to kill + reinit
#         (False, same_gdb) if it couldn’t halt for some reason, with no reinit done
#     """
#     for attempt in range(max_attempts):
#         # Try reading registers to see if GDB thinks it's halted:
#         try:
#             resp = gdb.send('-data-list-register-values x', timeout=2)
#         except Exception as e:
#             logger.warning(f"GDB command failed: {e}")
#             break

#         if resp.get('message') == 'done':
#             # Means the target was already halted
#             logger.debug("CPU is already halted.")
#             # return (True, gdb)
#             break
#         else:
#             # Not halted => send interrupt
#             logger.debug(f"CPU not halted => attempt={attempt+1}, sending interrupt.")
#             gdb.interrupt()
#             reason, payload = gdb.wait_for_stop(timeout=wait_timeout)
#             if reason == 'timed out':
#                 logger.warning("Interrupt timed out, the target may not have halted.")
#                 break
#             else:
#                 logger.debug(f"Got stop event => reason={reason}")
#                 if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
#                     # return (True, gdb)
#                     break
    
#     # If we get here, we tried everything max_attempts times and it's still not halted.
#     logger.error("Could not force CPU to halt after multiple attempts. Killing GDB.")
#     # new_gdb = gdb.kill_and_reinit_gdb(gdb, ELF_PATH)  # Re-init
#     # The new GDB is presumably halted at main or after reset, so we consider it halted.
#     # return (True, new_gdb)
#     return True

# def force_halt_if_running(gdb: GDB, max_attempts=3, wait_timeout=5):
#     # same code as original
#     for attempt in range(max_attempts):
#         resp = gdb.send('-data-list-register-values x', timeout=3)
#         if resp['message'] == 'done':
#             logger.debug("CPU is halted.")
#             return
#         else:
#             logger.debug(f"CPU not halted => attempt={attempt+1}, sending interrupt.")
#             gdb.interrupt()
#             while True:
#                 resp = gdb.send('-data-list-register-values x', timeout = 3)
#                 if resp['message'] == 'done':
#                     break
#                 reason, payload = gdb.wait_for_stop(timeout=wait_timeout)
#                 if reason == 'timed out':
#                     break
#                 if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
#                     break
#     halted = gdb.force_interrupt_or_kill(timeout=5)
#     raise Exception("Could not force CPU to halt after multiple attempts.")



# def force_halt_if_running(gdb: GDB, max_attempts=3):
#     for attempt in range(max_attempts):
        
#         # Check if GDB says it is already halted:
#         resp = gdb.send('-data-list-register-values x', timeout=3)
#         if resp['message'] == 'done':
#             logging.debug("CPU is halted, returning.")
#             return
#         # else try an interrupt
#         else:
#             gdb.interrupt()
#             reason, payload = gdb.wait_for_stop(timeout=5)
#             if reason.startswith("timed out"):
#                 halted = gdb.force_interrupt_or_kill(timeout=5)
#                 if halted:
#                     return
#     logging.error("Board not halting => re-initialize GDB from scratch.")

#     raise Exception("Could not halt CPU after multiple attempts, even after kill.")


def delete_all_breakpoints(gdb: GDB):
    # same code as original
    logger.debug("Deleting all existing breakpoints.")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        err = resp['payload'].get('msg', '')
        if 'No breakpoints to delete' not in err:
            raise Exception(f"Failed to delete breakpoints: {err}")
    else:
        logger.info("Deleted all breakpoints.")

def remove_breakpoints(gdb: GDB, bp_ids):
    # same code as original
    for bp_id in bp_ids:
        try:
            gdb.remove_breakpoint(bp_id)
            logger.info(f"Removed breakpoint id={bp_id}")
        except Exception as e:
            logger.warning(f"Could not remove breakpoint id={bp_id}: {e}")

def write_crashing_input(crash_data: bytes, crash_dir: str, filename: str) -> None:
    if not os.path.exists(crash_dir):
        os.makedirs(crash_dir, exist_ok=True)
    file_path = os.path.join(crash_dir, filename)
    logger.info(f"Writing crash input to {file_path} ...")
    with open(file_path, 'wb') as f:
        f.write(crash_data)

def restart_program(gdb: GDB, elf_path: str):
    logger.info("Restarting program from scratch...")
    gdb.send('monitor reset halt')
    gdb.send(f'-file-exec-and-symbols {elf_path}')
    gdb.send('-break-insert main')
    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        logger.warning("Could not run after restart; continuing.")
        gdb.continue_execution()

    reason, payload = gdb.wait_for_stop(timeout=10)
    if reason == 'timed out':
        raise Exception("Program did not halt at main after restart.")
    gdb.continue_execution()

def on_timeout(test_input: bytes, gdb, crash_dir: str) -> None:
    logger.warning("=== Timeout / Stuck detected ===")
    stacktrace_str = "timeout_no_stacktrace"
    try:
        # gdb.interrupt()
        gdb.send('monitor halt')
        time.sleep(10)
        resp = gdb.send('-stack-list-frames')
        if 'payload' in resp and 'stack' in  resp['payload']:
            frames = resp['payload']['stack']
            addresses = [frame['addr'] for frame in frames]
            stacktrace_str = "_".join(addresses[:4])
    except Exception as e:
        logger.warning(f"Could not retrieve stacktrace on timeout: {e}")

    timestamp_str = str(int(time.time()))
    stacktrace_str = re.sub(r'[^a-zA-Z0-9_]', '', stacktrace_str)
    filename = f"timeout_{timestamp_str}_{stacktrace_str}"
    # If want to store timeouts, do:
    # write_crashing_input(test_input, crash_dir, filename)

def on_crash(gdb: GDB, test_data: bytes, crash_dir: str) -> None:
    logger.warning("=== Target crash detected ===")
    stacktrace_str = "no_stacktrace"
    try:
        resp = gdb.send('-stack-list-frames')
        if 'payload' in resp and 'stack' in resp['payload']:
            frames = resp['payload']['stack']
            addresses = [frame['addr'] for frame in frames]
            stacktrace_str = "_".join(addresses[:4])
        else:
            logger.warning("No valid stack info in GDB response.")
    except Exception as e:
        logger.warning(f"Could not retrieve stacktrace: {e}")

    timestamp_str = str(int(time.time()))
    stacktrace_str = re.sub(r'[^a-zA-Z0-9_]', '', stacktrace_str)
    filename = f"crash_{timestamp_str}_{stacktrace_str}"

    write_crashing_input(test_data, crash_dir, filename)

def _handle_uses_for_def(gdb, stop_responses, inputs, test_data, def_addr_str, uses_list,
                         coverage_mgr, input_gen, crash_dir):
    logger.info(f"Handling uses for def={def_addr_str}. Found {len(uses_list)} uses.")
    uses_sorted = get_closest_uses(def_addr_str, uses_list)
    uses_idx = 0
    any_use_triggered = False

    while uses_idx < len(uses_sorted):
        uses_chunk = uses_sorted[uses_idx : uses_idx + HW_BREAKPOINT_LIMIT]
        uses_idx += HW_BREAKPOINT_LIMIT

        gdb = force_halt_if_running(gdb)

        uses_bp_map = {}
        for use_addr_str in uses_chunk:
            ubp_id = gdb.set_breakpoint(use_addr_str)
            uses_bp_map[ubp_id] = use_addr_str

        gdb.continue_execution()
        no_trigger_count = 0

        while uses_bp_map and no_trigger_count < MAX_USE_TRIES:
            # NEW pattern:
            # 1) Wait for the child process to say "input request" 
            #    (the board is sending 'A').
            # 2) Then we do inputs.put(test_data).

            reason2, payload2 = None, None
            # We do a small loop that tries to get "input request" from child
            # or a GDB stop event. We'll do a non-blocking check on GDB, 
            # or do a short timeout. This is just one possible approach.
            # The easiest approach might be:
            # child_ready = False
            inputs.put(test_data)
            # poll_timeout = time.time() + 5  # 5 second poll for 'input request'
            # while time.time() < poll_timeout and not child_ready:
            #     # First see if the child told us "input request"
            #     if not stop_responses.empty():
            #         reason_m, payload_m = stop_responses.get(block=False)
            #         if reason_m == 'input request':
            #             # Child wants data => we provide it
            #             inputs.put(test_data)
            #             child_ready = True
            #         else:
            #             logger.info(f"Got an unexpected child message: {reason_m}, {payload_m}")

                # Also check if GDB has stopped
            reason2, payload2 = gdb.wait_for_stop(timeout=5)
            # if reason2 not in (None, 'timed out'):
            #         # Means GDB actually reported something
            # why do I need break here?
            #         break

            # if child_ready is False:
            #     logger.info("Never got 'input request' from child within 5s. Possibly board didn't send 'A'.")
            
            # If reason2 was set to something from GDB, handle it
            if not reason2:
                # We got no GDB event => poll again
                reason2, payload2 = gdb.wait_for_stop(timeout=3)

            if reason2 in ("breakpoint hit", "stopped, no reason given"):
                if payload2 in uses_bp_map:
                    use_addr = uses_bp_map[payload2]
                    logger.info(f"Use triggered => {use_addr}")
                    coverage_mgr.update_coverage_for_defuse(def_addr_str, use_addr)

                    remove_breakpoints(gdb, [payload2])
                    del uses_bp_map[payload2]
                    gdb.continue_execution()

                    any_use_triggered = True
                    no_trigger_count = 0
                else:
                    logger.info(f"Unknown breakpoint => {payload2}, continuing.")
                    pc_resp = gdb.send('-data-evaluate-expression $pc')
                    pc_val_str = pc_resp['payload'].get('value', '')
                    if pc_val_str:
                        pc_str = pc_val_str.split()[0]
                        coverage_mgr.update_coverage_for_def(pc_str)

                    remove_breakpoints(gdb, [payload2])
                    any_use_triggered = True
                    gdb.continue_execution()

            elif reason2 == 'timed out':
                logger.info("No use triggered this attempt.")
                no_trigger_count += 1

            elif reason2 in ('exited','crashed'):
                logger.warning(f"Target {reason2} => treat as crash for uses, restarting.")
                any_use_triggered = True
                on_crash(gdb, test_data, crash_dir)
                restart_program(gdb, ELF_PATH)
                break
            else:
                logger.info(f"Unknown reason => {reason2}, continuing.")
                gdb.continue_execution()

        timestamp = int(time.time())
        # input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

        if coverage_mgr.check_new_coverage():
            any_use_triggered = True
            logger.info("New coverage from uses => add input to corpus.")
            input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
            input_gen.choose_new_baseline_input()
        #this sentence. 
        gdb = force_halt_if_running(gdb)
        time.sleep(1)
        #here's a problem
        if uses_bp_map:
            remove_breakpoints(gdb, list(uses_bp_map.keys()))
            uses_bp_map.clear()

        logger.info(f"End of use chunk, continuing to next chunk.")
        gdb.continue_execution()

    return any_use_triggered

def create_serial_connection():
    """
    Helper: build a config object for SerialConnection,
    plus two queues (stop_responses & inputs).
    """
    config = configparser.ConfigParser()
    config['SUTConnection'] = {
        'port': SERIAL_PORT,
        'baud_rate': str(BAUD_RATE),
        'serial_timeout': str(SERIAL_TIMEOUT)
    }
    sut_conf = config['SUTConnection']

    stop_responses = mp.Queue()
    inputs = mp.Queue()

    def no_op_reset():
        pass

    conn = SerialConnection(
        stop_responses=stop_responses,
        SUTConnection_config=sut_conf,
        inputs=inputs,
        reset_sut=no_op_reset
    )
    return conn, stop_responses, inputs


def build_lookup_for_chunk(chunk: list[tuple[str, list[str]]], all_block_info: dict) -> dict[str, dict]:

    lookup = {}

    # For each (definition, uses_list) in the chunk...
    for def_addr, uses_list in chunk:
        found_block = None
        found_def_entry = None

        # 1) Find which block has that def_addr
        for block_hex, definitions in all_block_info.items():
            for d in definitions:
                if d["def_addr"] == def_addr:
                    found_block = block_hex
                    found_def_entry = d
                    break
            if found_block is not None:
                break

        if found_block is None:
           
            lookup[def_addr] = {
                "def_block": None,
                "uses": []
            }
            continue

       
        uses_data = []
        for use_addr in uses_list:
            if use_addr in found_def_entry["use_addrs"]:
                i = found_def_entry["use_addrs"].index(use_addr)
                if i < len(found_def_entry["use_block_addrs"]):
                    block_hex_for_use = found_def_entry["use_block_addrs"][i]
                    uses_data.append({
                        "use_addr": use_addr,
                        "use_block": block_hex_for_use
                    })
                else:
                    uses_data.append({
                        "use_addr": use_addr,
                        "use_block": None
                    })
            else:
                uses_data.append({
                    "use_addr": use_addr,
                    "use_block": None
                })

        lookup[def_addr] = {
            "def_block": found_block,
            "uses": uses_data
        }

    return lookup

def build_block_lookup_for_coverage(parsed_data: dict) -> dict[str, dict]:
    coverage_lookup: dict[str, dict] = {}

    def get_or_create_block_info(block_hex: str) -> dict:
        """Helper: ensure coverage_lookup[block_hex] has two lists."""
        if block_hex not in coverage_lookup:
            coverage_lookup[block_hex] = {
                "def_block_addrs": [],   # definitions in this block
                "def_use_pairs": []      # (def_addr, use_addr) pairs that get covered if we hit this block
            }
        return coverage_lookup[block_hex]

    # Traverse every definition-block in the parsed data
    for block_addr, defs_list in parsed_data.items():
        # block_addr is e.g. "0x1000"
        # defs_list is a list of dicts: { "def_addr": "...", "use_addrs": [...], "use_block_addrs": [...] }

        # For the block where the definitions live:
        block_info = get_or_create_block_info(block_addr)

        for def_item in defs_list:
            # e.g. def_item = {
            #   "def_addr": "0x1008",
            #   "use_addrs": ["0x1010", "0x1014"],
            #   "use_block_addrs": ["0x1010", "0x1014"]
            # }
            def_a = def_item["def_addr"]
            block_info["def_block_addrs"].append(def_a)

            # Pair up each use_block with each use_addr
            for use_block_hex, use_addr_hex in zip(
                    def_item["use_block_addrs"],
                    def_item["use_addrs"]
            ):
                # If we hit 'use_block_hex', that means coverage for (def_a, use_addr_hex)
                use_block_info = get_or_create_block_info(use_block_hex)
                use_block_info["def_use_pairs"].append((def_a, use_addr_hex))

    return coverage_lookup

def on_block_hit(block_hex: str, coverage_mgr, coverage_lookup):
    # 1) Mark coverage for the block itself
    coverage_mgr.update_coverage_for_def(block_hex)

    # 2) Mark coverage for every definition in that block
    block_info = coverage_lookup.get(block_hex)
    if not block_info:
        return
    for def_addr_str in block_info["def_block_addrs"]:
        coverage_mgr.update_coverage_for_def(def_addr_str)
        logger.info("new coverage for def-use chain in basic block level")


def main():
    logger.info("=== Starting main with snippet-based SerialConnection ===")

    coverage_mgr = CoverageManager()
    # Initialize GDB
    logger.debug("Initialize GDB & load ELF.")
    

    # Load def-use
    # for testing, we'll just parse the file here
    # all_defs = parse_def_use_file(DEF_USE_FILE)
    # all_defs = parse_external(DEF_USE_FILE)
    all_block = parse_block(DEF_USE_FILE)
    all_block_with_information = parse_block_with_full_details(DEF_USE_FILE)
    coverage_lookup = build_block_lookup_for_coverage(all_block_with_information)

    all_defs = convert_parsed_to_blocklist(all_block_with_information)

# 45000 
# 160 days 7.5 hours 45/260/7.5

    if not all_defs:
        logger.error("No defs found => exit.")
        # for def model comment return
        # return
    if not all_block:
        logger.error("No block found => exit.")

    # CREATE & START the snippet-based SerialConnection
    conn, stop_responses, inputs = create_serial_connection()
    conn.start()

    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
    )

    crash_dir = os.path.join(OUTPUT_DIRECTORY, "crashes")
    timeout_dir = os.path.join(OUTPUT_DIRECTORY, "timeouts")
    logger.info("GDB & SerialConnection initialized.")
    gdb = GDB(
        gdb_path='gdb-multiarch',
        gdb_server_address='localhost:2331',
        software_breakpoint_addresses=[],
        consider_sw_breakpoint_as_error=False
    )

    # Start GDB session
    gdb.connect(ELF_PATH)
    gdb.send('monitor reset')
    gdb.send('monitor halt')
    gdb.send(f'-file-exec-and-symbols {ELF_PATH}')
    gdb.send('-break-insert main')
    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        logger.warning("Could not run => continuing.")
        gdb.continue_execution()

    reason, payload = gdb.wait_for_stop(timeout=10)
    logger.info(f"Initial stop => reason={reason}, payload={payload}")
    if reason in ("breakpoint hit", "stopped, no reason given"):
        gdb.continue_execution()
    
    # for k in range(10):
    #     gdb.continue_execution()
    #     gdb = gdb.kill_and_reinit_gdb(gdb, ELF_PATH)
    #     gdb.wait_for_stop(timeout=3)
    #     if not gdb.gdb_communicator.is_alive():
    #         logger.error("New GDB communicator is not alive. Something went wrong.")    
    #     logger.info("testing")
    
    # gdb = gdb.kill_and_reinit_gdb(gdb, ELF_PATH)

    try:
        round_count = 0
        coverage_changed = True

        while round_count < NUM_ROUNDS:
            round_count += 1
            logger.info(f"=== Starting Round #{round_count} ===")

            # Generate 1 test input if coverage changed, else skip
            if coverage_changed:
                input_gen.choose_new_baseline_input()
                test_data = input_gen.generate_input()
                logger.info(f"Round #{round_count} => test_data={test_data!r}")
            else:
                logger.info("No new coverage => skipping test generation.")
            coverage_changed = False

            def_generator = get_defs_in_weighted_random_order(all_defs)
            # logger.info(f"{all_defs}")
            # logger.info(f"{def_generator}")
            # change this to apply the block

            # def_generator = iter(all_block)

            # no need def_generator = get_defs_in_weighted_random_order(all_block)
            done_with_round = False

            while not done_with_round:
                chunk = []
                for _ in range(HW_BREAKPOINT_LIMIT):
                    try:
                        d_str, u_list = next(def_generator)
                        # logger.info(f"Next def => {d_str}")
                        chunk.append((d_str, u_list))

                        # block_addr = next(def_generator)
                        # chunk.append(block_addr)
                    except StopIteration:
                        break
                if not chunk:
                    logger.info("Exhausted all defs => new test next round.")
                    break

                gdb = force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)

                def_bp_map = {}
                for def_addr, uses_list in chunk:
                    bp_id = gdb.set_breakpoint(def_addr)
                    def_bp_map[bp_id] = (def_addr, uses_list)

                # for block_addr in chunk:
                #     bp_id = gdb.set_breakpoint(block_addr)
                #     def_bp_map[bp_id] = block_addr
                    

                gdb.continue_execution()
                no_trigger_count = 0

                while def_bp_map and no_trigger_count < MAX_DEF_TRIES_PER_CHUNK:
                    logger.info(f"[DEF chunk attempt] => will wait for 'input request'")
                    
                    # WAIT for child process or GDB stop:
                    child_ready = False
                    reasonC, payloadC = None, None
                    poll_timeout = time.time() + 10  # 10 second poll for 'input request'

                    while time.time() < poll_timeout and not child_ready:
                        # Check if child says 'input request'
                        if not stop_responses.empty():
                            rC, pC = stop_responses.get(block=False)
                            # if rC == 'input request':
                                # Provide test_data
                            logger.info(f"Child requested input => provide. sending {test_data}.")
                            inputs.put(test_data)
                            child_ready = True
                            # else:
                            #     logger.info(f"Child message: {rC}, {pC}")
                        # else:
                        #     logger.info("Checking GDB for stop.")

                        # Also see if GDB gave a stop
                        reasonC, payloadC = gdb.wait_for_stop(timeout=0.2)
                        if reasonC not in (None, 'timed out'):
                            break

                    if not child_ready:
                        logger.debug("No 'input request' from board within 5s? Possibly no 'A' from firmware.")

                    if not reasonC:
                        reasonC, payloadC = gdb.wait_for_stop(timeout=3)

                    logger.info(f"GDB => reason={reasonC}, payload={payloadC}")

                    if reasonC in ("breakpoint hit", "stopped, no reason given"):
                        if payloadC in def_bp_map:
                            def_addr_str, uses_list = def_bp_map[payloadC]
                            # block_addr = def_bp_map[payloadC]
                            increment_bp_hit_count(def_addr_str)
                            logger.info(f"Def triggered => {def_addr_str}")
                            coverage_mgr.update_coverage_for_def(def_addr_str)

                            on_block_hit(def_addr_str, coverage_mgr, coverage_lookup)


                            remove_breakpoints(gdb, [payloadC])
                            del def_bp_map[payloadC]

                            no_trigger_count = 0

                            gdb = force_halt_if_running(gdb)
                            if uses_list:
                                use_status = _handle_uses_for_def(
                                    gdb, stop_responses, inputs,
                                    test_data, def_addr_str, uses_list,
                                    coverage_mgr, input_gen, crash_dir
                                )
                                coverage_changed = coverage_changed or use_status

                            if def_bp_map:
                                gdb.continue_execution()

                        else:
                            logger.debug(f"Unknown breakpoint => {payloadC}, continuing.")
                            pc_resp = gdb.send('-data-evaluate-expression $pc')
                            pc_val_str = pc_resp['payload'].get('value','')
                            if pc_val_str:
                                pc_str = pc_val_str.split()[0]
                                coverage_mgr.update_coverage_for_def(pc_str)
                            remove_breakpoints(gdb, [payloadC])
                            gdb.continue_execution()

                    elif reasonC == 'timed out':
                        on_timeout(test_data, gdb, timeout_dir)
                        logger.debug("No def triggered => timed out.")
                        no_trigger_count += 1

                    elif reasonC in ('exited','crashed'):
                        logger.warning(f"Target {reasonC} => treat as crash, restarting.")
                        coverage_changed = True
                        on_crash(gdb, test_data, crash_dir)
                        restart_program(gdb, ELF_PATH)
                        break

                    else:
                        logger.warning(f"Unexpected stop => reason={reasonC}, payload={payloadC}")
                        coverage_changed = True
                        if reasonC == 'interrupt':
                            logger.warning("Interrupt => treat as crash.")
                        break
                        # gdb.continue_execution()

                    if not def_bp_map:
                        break

                # Coverage check
                timestamp = int(time.time())
                # input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

                if coverage_mgr.check_new_coverage():
                    coverage_changed = True
                    logger.info("New coverage found => add input to corpus.")
                    input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
                    input_gen.choose_new_baseline_input()

                gdb = force_halt_if_running(gdb)
                if def_bp_map:
                    remove_breakpoints(gdb, list(def_bp_map.keys()))
                    def_bp_map.clear()

                gdb.continue_execution()
                done_with_round = True

            # coverage_mgr.reset_coverage()
            logger.info(f"End of round #{round_count}, coverage not been reset.\n")

    except KeyboardInterrupt:
        logger.info("Stopped by user.")
    # finally:
    #     # Kill the child process for the serial connection
    #     import signal
    #     os.kill(conn.pid, signal.SIGUSR1)
    #     conn.join()

    #     coverage_mgr.close()
    #     gdb.stop()
    #     logger.info("Clean exit from main().")
    finally:
        import signal
        logger.info("Cleaning up...")
        os.kill(conn.pid, signal.SIGUSR1)
        conn.join()
        logger.info("Serial connection closed.")
        coverage_mgr.close()
        gdb.stop()
        logger.info("GDB connection closed.")

if __name__ == '__main__':
    main()
