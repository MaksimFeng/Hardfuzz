import os
import time
import random
import logging
import logging.handlers
import re
import configparser
import multiprocessing as mp

#change the breakpoint to hardware breakpoint

# Import your coverage manager, GDB, etc.
from fuzzing.coverage_manager import CoverageManager
from config.settings import (
    LOG_LEVEL, LOG_FORMAT, LOG_DATEFMT, LOG_FILE,
    SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
    OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
    NO_TRIGGER_THRESHOLD
)
from fuzzing.gdb_interface import GDB
from fuzzing.input_generation import InputGeneration
from utils.file_parsing import parse_def_use_file
from utils.file_parsing import parse_external
from utils.file_parsing import parse_block
# Import the new snippet-based connection classes:
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

def get_defs_in_weighted_random_order(all_defs):
    # Same code as your original
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

def force_halt_if_running(gdb: GDB, max_attempts=3, wait_timeout=5):
    # same code as original
    for attempt in range(max_attempts):
        resp = gdb.send('-data-list-register-values x', timeout=3)
        if resp['message'] == 'done':
            logger.debug("CPU is halted.")
            return
        else:
            logger.debug(f"CPU not halted => attempt={attempt+1}, sending interrupt.")
            gdb.interrupt()
            while True:
                reason, payload = gdb.wait_for_stop(timeout=wait_timeout)
                if reason == 'timed out':
                    break
                if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
                    break
    raise Exception("Could not force CPU to halt after multiple attempts.")

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
        time.sleep(1)
        resp = gdb.send('-stack-list-frames')
        if 'payload' in resp and 'stack' in resp['payload']:
            frames = resp['payload']['stack']
            addresses = [frame['addr'] for frame in frames]
            stacktrace_str = "_".join(addresses[:4])
    except Exception as e:
        logger.warning(f"Could not retrieve stacktrace on timeout: {e}")

    timestamp_str = str(int(time.time()))
    stacktrace_str = re.sub(r'[^a-zA-Z0-9_]', '', stacktrace_str)
    filename = f"timeout_{timestamp_str}_{stacktrace_str}"
    # If you want to store timeouts, do:
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

        force_halt_if_running(gdb)

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
            reason2, payload2 = gdb.wait_for_stop(timeout=0.2)
            if reason2 not in (None, 'timed out'):
                    # Means GDB actually reported something
                    break

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
        input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

        if coverage_mgr.check_new_coverage():
            any_use_triggered = True
            logger.info("New coverage from uses => add input to corpus.")
            input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
            input_gen.choose_new_baseline_input()

        force_halt_if_running(gdb)
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

def main():
    logger.info("=== Starting main with snippet-based SerialConnection ===")

    coverage_mgr = CoverageManager()
    # Initialize GDB
    logger.debug("Initialize GDB & load ELF.")
    

    # Load def-use
    # for testing, we'll just parse the file here
    all_defs = parse_def_use_file(DEF_USE_FILE)
    # all_defs = parse_external(DEF_USE_FILE)
    all_block = parse_block(DEF_USE_FILE)

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

                force_halt_if_running(gdb)
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
                    poll_timeout = time.time() + 5

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

                            remove_breakpoints(gdb, [payloadC])
                            del def_bp_map[payloadC]

                            no_trigger_count = 0

                            force_halt_if_running(gdb)
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
                        gdb.continue_execution()

                    if not def_bp_map:
                        break

                # Coverage check
                timestamp = int(time.time())
                input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

                if coverage_mgr.check_new_coverage():
                    coverage_changed = True
                    logger.info("New coverage found => add input to corpus.")
                    input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
                    input_gen.choose_new_baseline_input()

                force_halt_if_running(gdb)
                if def_bp_map:
                    remove_breakpoints(gdb, list(def_bp_map.keys()))
                    def_bp_map.clear()

                gdb.continue_execution()
                done_with_round = True

            coverage_mgr.reset_coverage()
            logger.info(f"End of round #{round_count}, coverage reset.\n")

    except KeyboardInterrupt:
        logger.info("Stopped by user.")
    finally:
        # Kill the child process for the serial connection
        import signal
        os.kill(conn.pid, signal.SIGUSR1)
        conn.join()

        coverage_mgr.close()
        gdb.stop()
        logger.info("Clean exit from main().")

if __name__ == '__main__':
    main()
