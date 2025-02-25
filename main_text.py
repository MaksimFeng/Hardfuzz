import os
import time
import random
import logging
import logging.handlers
import serial
import re
from fuzzing.coverage_manager import CoverageManager
from config.settings import (
    LOG_LEVEL, LOG_FORMAT, LOG_DATEFMT, LOG_FILE,
    SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
    OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
    NO_TRIGGER_THRESHOLD
)
from fuzzing.gdb_interface import GDB
from fuzzing.input_generation import InputGeneration
from communication.serial_comm import send_test_case, process_response
from utils.file_parsing import parse_def_use_file

HW_BREAKPOINT_LIMIT = 6
# 6
MAX_DEF_TRIES_PER_CHUNK = 1
MAX_USE_TRIES = 1
NUM_ROUNDS = 999999
# global dic for the numbers of the def/breakpoint has been hit across rounds
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
    weighted_list = []
    local_usage_count = {}
    original_weight = {}
    for d_str, u_list in all_defs:
        local_usage_count[d_str] = 0 # add the dictionary for the def count, this is for updating the weight
        base_w = max(1, len(u_list))
        # trying to dividede by ten
        # trying to count how many times the def is used dictionary
        # and reduce the weight according to the counts. 

        # original_weight[d_str] = w
        weighted_list.append((d_str, u_list, base_w))
        local_usage_count[d_str] = 0

    while weighted_list:
        total_weight = 0.0
        new_list = []
        for i, (d_str, u_list, base_w) in enumerate(weighted_list):
            loc_hit = local_usage_count[d_str]
            glob_hits = global_hit_counts.get(d_str, 0)
            scale = (1.0 / (1 + loc_hit)) * (1.0 / (1 + glob_hits) ** 0.5)
            w = base_w * scale
            # print(f"def={d_str}, base_w={base_w}, loc_hit={loc_hit}, glob_hits={glob_hits}, scale={scale}, w={w}")
            new_list.append((d_str, u_list, w))
            total_weight += w
        # total_weight = sum(item[2] for item in weighted_list)
        # #delete this, this will never be true
        # if total_weight <= 0:
        #     for (d, u, w) in weighted_list:
        #         yield (d, u)
        #     return

        r = random.random() * total_weight
        cumulative = 0.0
        for i, (d, u, w) in enumerate(weighted_list):
            cumulative += w
            if cumulative >= r:
                yield (d, u)
                local_usage_count[d] += 1
                # new_weight = max(1, original_weight[d] //(2 ** local_usage_count[d]))
                # new_weight = max(1, original_weight[d] //  (1 + local_usage_count[d]))
                # weighted_list[i] = (d, u, new_weight)
                # weighted_list.pop(i)
                break

def get_closest_uses(def_addr_str, uses_list):
    def_addr = int(def_addr_str, 16)
    return sorted(uses_list, key=lambda u: abs(int(u, 16) - def_addr))

def force_halt_if_running(gdb: GDB, max_attempts=3, wait_timeout=5):
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
    """
    Removes all breakpoints from GDB.
    """
    logger.debug("Deleting all existing breakpoints.")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        err = resp['payload'].get('msg', '')
        if 'No breakpoints to delete' not in err:
            raise Exception(f"Failed to delete breakpoints: {err}")
    else:
        logger.info("Deleted all breakpoints.")

def remove_breakpoints(gdb: GDB, bp_ids):
    """
    Removes only the specified list of breakpoint IDs from GDB.
    """
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
    """
    Handle an infinite loop or board-stuck scenario the same as a crash.
    1) Attempt to retrieve a partial stack trace
    2) Build a 'timeout' filename
    3) Write out the input
    """
    logger.warning("=== Timeout / Stuck detected ===")

    stacktrace_str = "timeout_no_stacktrace"
    try:
        # Force an interrupt so we can get frames
        gdb.interrupt()
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
    # every time the timeout is called, the file is written, but we don't store them. there're too many of them.
    # write_crashing_input(test_input, crash_dir, filename)


def on_crash(gdb: GDB, test_data: bytes, crash_dir: str) -> None:
    """
    Handle a crash condition:
    1) Attempt to get a stack trace from GDB
    2) Build a filename (e.g. using timestamp + partial trace)
    3) Write out the crashing input
    """
   
    logger.warning("=== Target crash detected ===")
    # # Attempt to get a stacktrace
    # stacktrace_str = "no_stacktrace"
    # try:
    #     resp = gdb.send('-stack-list-frames')
    #     if 'payload' in resp and 'stack' in resp['payload']:
    #         frames = resp['payload']['stack']
    #         # Basic example: gather the addresses (limit to avoid huge filenames)
    #         stack_addrs = [frame['addr'] for frame in frames]
    #         # Join them up to some limit
    #         short_trace = "_".join(stack_addrs[:4])  # just the first few frames
    #         # Make it filename-safe:
    #         short_trace = "".join(c for c in short_trace if c.isalnum() or c in '_')
    #         stacktrace_str = short_trace if short_trace else "empty"
    # except Exception as e:
    #     logger.warning(f"Could not retrieve stacktrace: {e}")
    stacktrace = '' 
    stacktrace_str = "no_stacktrace"
    try:
        resp = gdb.send('-stack-list-frames')
        # Make sure the response is valid
        if 'payload' in resp and 'stack' in resp['payload']:
            frames = resp['payload']['stack']
            # Collect frame addresses (or function names)
            addresses = [frame['addr'] for frame in frames]
            # Just combine them as a short string
            # e.g., '0x08001234_0x08005678'
            stacktrace_str = "_".join(addresses[:4])  # limit to ~4 frames
        else:
            logger.warning("No valid stack info in GDB response. Payload missing or invalid.")
    except Exception as e:
        logger.warning(f"Could not retrieve stacktrace: {e}")

    # Build a crash filename. For example:
    # crash_<timestamp>_<some-stack-frames>
    timestamp_str = str(int(time.time()))
    # Clean out weird characters from stacktrace so it's a safe filename
    stacktrace_str = re.sub(r'[^a-zA-Z0-9_]', '', stacktrace_str)

    # Combine them
    filename = f"crash_{timestamp_str}_{stacktrace_str}"

    # Write the input
    write_crashing_input(test_data, crash_dir, filename)
    # Save the crashing input
    # filename = f"{int(time.time())}_{stacktrace_str}"
    # filepath = os.path.join(crash_dir, filename)
    # os.makedirs(crash_dir, exist_ok=True)

    # logger.warning(f"Saving crash testcase as: {filepath}")
    # with open(filepath, 'wb') as f:
    #     f.write(test_data)
    if len(stacktrace) > 100:
            stacktrace = stacktrace[0:100]
        
        # Make string os file name friendly 
#     stacktrace = "".join([c for c in stacktrace if re.match(r'\w', c)])
#     write_crashing_input(test_data, stacktrace_str)
# def write_crashing_input(
#             self,
#             current_input: bytes,
#             filename: str
#     ) -> None:
#         filepath = os.path.join(self.crashes_directory, filename)
#         if os.path.isfile(filepath):
#             log.info(f'Found duplicate crash with {current_input=}')
#             return

#         with open(filepath, 'wb') as f:
#             log.info(f'New crash with {current_input=}')
#             f.write(current_input)

# def on_timeout(gdb: GDB, test_data: bytes, timeout_dir: str) -> None:
#     """
#     Enriched timeout handler: forcibly halts, optionally collects stack info,
#     and stores the input in a dedicated 'timeouts' directory.
#     """
#     logger.warning("=== Timeout detected ===")
#     # Interrupt to gather any debug info
#     gdb.interrupt()
#     time.sleep(1)  # short wait for target to stop

#     stacktrace_str = "timeout_no_stacktrace"
#     try:
#         resp = gdb.send('-stack-list-frames')
#         if 'payload' in resp and 'stack' in resp['payload']:
#             frames = resp['payload']['stack']
#             stack_addrs = [frame['addr'] for frame in frames]
#             short_trace = "_".join(stack_addrs[:4])  # just the first few frames
#             short_trace = "".join(c for c in short_trace if c.isalnum() or c in '_')
#             stacktrace_str = short_trace if short_trace else "empty"
#     except Exception as e:
#         logger.warning(f"Could not retrieve stacktrace on timeout: {e}")

#     filename = f"{int(time.time())}_{stacktrace_str}"
#     filepath = os.path.join(timeout_dir, filename)
#     os.makedirs(timeout_dir, exist_ok=True)

#     logger.warning(f"Saving timeout testcase as: {filepath}")
#     with open(filepath, 'wb') as f:
#         f.write(test_data)


def main():
    logger.info("=== Starting main with 'one testcase until def/use triggers' ===")

    coverage_mgr = CoverageManager()

    # Initialize GDB
    logger.debug("Initialize GDB & load ELF.")
    gdb = GDB(
        gdb_path='gdb-multiarch',
        gdb_server_address='localhost:2331',
        software_breakpoint_addresses=[],
        consider_sw_breakpoint_as_error=False
    )

    gdb.connect(ELF_PATH)
    gdb.send('monitor reset halt')
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

    # Load definitions
    all_defs = parse_def_use_file(DEF_USE_FILE)
    if not all_defs:
        logger.error("No defs found => exit.")
        return

    # Serial + Input generation
    # restart_program(gdb, ELF_PATH)
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
    time.sleep(2)

    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
    )

    crash_dir = os.path.join(OUTPUT_DIRECTORY, "crashes")
    timeout_dir = os.path.join(OUTPUT_DIRECTORY, "timeouts")

    try:
        round_count = 0
        test_case = b""
        coverage_changed = True
        while round_count < NUM_ROUNDS:
            round_count += 1
            logger.info(f"=== Starting Round #{round_count} ===")

            # (A) Generate exactly 1 test
            if coverage_changed:
                input_gen.choose_new_baseline_input()
                test_data = input_gen.generate_input()
                logger.info(f"Round #{round_count} => test_data={test_data!r}")
            else:
                # test_data = input_gen.generate_input()
                # logger.info(f"Round #{round_count} => test_data={test_data!r} (reused)")
                logger.info("No new coverage => skipping test generation.")
            coverage_changed = False
            def_generator = get_defs_in_weighted_random_order(all_defs)
            done_with_round = False

            while not done_with_round:
                # chunk up to 6
                chunk = []
                for _ in range(HW_BREAKPOINT_LIMIT):
                    try:
                        d_str, u_list = next(def_generator)
                        chunk.append((d_str, u_list))
                    except StopIteration:
                        break

                if not chunk:
                    logger.info("Exhausted all defs in this pass => new test next round.")
                    break

                force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)

                # Create a mapping from breakpoint_id -> (def_addr, uses_list)
                def_bp_map = {}
                for def_addr, uses_list in chunk:
                    bp_id = gdb.set_breakpoint(def_addr)
                    def_bp_map[bp_id] = (def_addr, uses_list)

                gdb.continue_execution()
                no_trigger_count = 0

                while def_bp_map and no_trigger_count < MAX_DEF_TRIES_PER_CHUNK:
                    logger.info(f"[DEF chunk attempt] => sending {test_data!r}")
                    # try:
                    resp = send_test_case(ser, test_data)
                    # except RuntimeError as e:
                    #     if str(e) == "BoardStuckTimeout":
                    #         logger.warning("Board stuck => treat as crash.")
                    #         on_crash(gdb, test_data, crash_dir)
                    #         restart_program(gdb, ELF_PATH)
                    process_response(resp)

                    reason, payload = gdb.wait_for_stop(timeout=3)
                    logger.debug(f"GDB => reason={reason}, payload={payload}")

                    if reason in ("breakpoint hit", "stopped, no reason given"):
                        if payload in def_bp_map:
                            def_addr_str, uses_list = def_bp_map[payload]
                            increment_bp_hit_count(def_addr_str)

                            logger.info(f"Def triggered => {def_addr_str}")
                            # Update coverage to check if this is the new coverage.
                            coverage_mgr.update_coverage_for_def(def_addr_str)

                            remove_breakpoints(gdb, [payload])
                            del def_bp_map[payload]

                            no_trigger_count = 0

                            force_halt_if_running(gdb)
                            if uses_list:
                                use_status = _handle_uses_for_def(
                                    gdb, ser, test_data,
                                    def_addr_str, uses_list,
                                    coverage_mgr, input_gen, crash_dir
                                )
                                coverage_changed = use_status

                            if def_bp_map:
                                gdb.continue_execution()

                        else:
                            logger.debug(f"Unknown breakpoint => {payload}, continuing.")
                            pc_resp = gdb.send('-data-evaluate-expression $pc')
                            pc_val_str = pc_resp['payload'].get('value','')
                            if pc_val_str:
                                pc_str = pc_val_str.split()[0]
                                coverage_mgr.update_coverage_for_def(pc_str)
                            remove_breakpoints(gdb, [payload])
                            gdb.continue_execution()

                    elif reason == 'timed out':
                        on_timeout(test_data, gdb, timeout_dir)
                        coverage_changed = True
                        logger.debug("No def triggered this attempt.")
                        no_trigger_count += 1

                    elif reason in ('exited','crashed'):
                        logger.warning(f"Target {reason} => treat as crash, restarting.")
                        coverage_changed = True
                        on_crash(gdb, test_data, crash_dir)
                        restart_program(gdb, ELF_PATH)
                        break

                    else:
                        # Possibly an interrupt or any other reason
                        logger.warning(f"Unexpected stop => reason={reason}, payload={payload}")
                        coverage_changed = True

                        if reason == 'interrupt':
                            logger.warning("Interrupt => treat as crash.")
                            # on_crash(gdb, test_data, crash_dir)
                        # on_crash(gdb, test_data, crash_dir)
                        gdb.continue_execution()

                    # If no BPs left => chunk is done
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

                # Cleanup breakpoints
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
        ser.close()
        coverage_mgr.close()
        gdb.stop()
        logger.info("Clean exit from main().")

def _handle_uses_for_def(gdb, ser, test_data, def_addr_str, uses_list,
                         coverage_mgr, input_gen, crash_dir):
    logger.info(f"Handling uses for def={def_addr_str}. Found {len(uses_list)} uses.")
    uses_sorted = get_closest_uses(def_addr_str, uses_list)
    uses_idx = 0

    any_use_triggered = False

    while uses_idx < len(uses_sorted):
        uses_chunk = uses_sorted[uses_idx : uses_idx + HW_BREAKPOINT_LIMIT]
        uses_idx += HW_BREAKPOINT_LIMIT

        force_halt_if_running(gdb)
        # delete_all_breakpoints(gdb)

        uses_bp_map = {}
        for use_addr_str in uses_chunk:
            ubp_id = gdb.set_breakpoint(use_addr_str)
            uses_bp_map[ubp_id] = use_addr_str

        gdb.continue_execution()

        no_trigger_count = 0
        while uses_bp_map and no_trigger_count < MAX_USE_TRIES:
            logger.info(f"[Use Attempt] => sending {test_data!r}")
            resp = send_test_case(ser, test_data)
            process_response(resp)

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
                    logger.info(f"{reason2}, {payload2}")
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

        # Coverage check
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

if __name__ == '__main__':
    main()
