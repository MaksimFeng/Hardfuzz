import os
import time
import random
import logging
import logging.handlers
import serial

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
MAX_DEF_TRIES_PER_CHUNK = 1
MAX_USE_TRIES = 1
NUM_ROUNDS = 999999

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

def get_defs_in_weighted_random_order(all_defs):
    weighted_list = []
    for d_str, u_list in all_defs:
        w = max(1, len(u_list))
        weighted_list.append((d_str, u_list, w))

    while weighted_list:
        total_weight = sum(item[2] for item in weighted_list)
        if total_weight <= 0:
            for (d, u, w) in weighted_list:
                yield (d, u)
            return

        r = random.random() * total_weight
        cumulative = 0.0
        for i, (d, u, w) in enumerate(weighted_list):
            cumulative += w
            if cumulative >= r:
                yield (d, u)
                weighted_list.pop(i)
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

# [ADDED]
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
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
    time.sleep(2)

    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
    )

    try:
        round_count = 0
        while round_count < NUM_ROUNDS:
            round_count += 1
            logger.info(f"=== Starting Round #{round_count} ===")

            # (A) Generate exactly 1 test
            test_data = input_gen.generate_input()
            logger.info(f"Round #{round_count} => test_data={test_data!r}")

            # Weighted-random generator of all defs
            def_generator = get_defs_in_weighted_random_order(all_defs)
            done_with_round = False
            #for current implement, the code run once the brekapoint is triggered, all the breakpoints will be deleted after that. which will cause the fuzzing miss some definitions at the same group. 
            # the another problem is that for one testcase, it will only stop after the def is triggered, which will cause the testcase not to be tested for the other defs in the same group. and lack of the whole coverage map. 
            #- the thing I need to do is that I need to fix the first problem and for second one, make for one testcase, it will iterate all the defs and related uses. after that, the next testcase will be tested.
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

                # [MODIFIED] Instead of deleting all breakpoints each time, we only
                # do it once before setting a new chunk. This helps keep GDB clean
                force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)
                
                # Create a mapping from breakpoint_id -> (def_addr, uses_list)
                def_bp_map = {}
                for def_addr, uses_list in chunk:
                    bp_id = gdb.set_breakpoint(def_addr)
                    def_bp_map[bp_id] = (def_addr, uses_list)

                gdb.continue_execution()
                no_trigger_count = 0
                # We'll attempt to trigger these chunk breakpoints for up to MAX_DEF_TRIES_PER_CHUNK times
                # but we won't remove them all if only some triggers occur.
                while def_bp_map and no_trigger_count < MAX_DEF_TRIES_PER_CHUNK:
                    logger.info(f"[DEF chunk attempt] => sending {test_data!r}")
                    resp = send_test_case(ser, test_data)
                    process_response(resp)

                    reason, payload = gdb.wait_for_stop(timeout=3)
                    logger.debug(f"GDB => reason={reason}, payload={payload}")

                    if reason in ("breakpoint hit", "stopped, no reason given"):
                        if payload in def_bp_map:
                            def_addr_str, uses_list = def_bp_map[payload]
                            logger.info(f"Def triggered => {def_addr_str}")
                            coverage_mgr.update_coverage_for_def(def_addr_str)

                            # remove only this triggered breakpoint
                            remove_breakpoints(gdb, [payload])
                            del def_bp_map[payload]

                            # Because something triggered, reset the no-trigger count
                            no_trigger_count = 0

                            # Immediately handle uses for this def
                            force_halt_if_running(gdb)
                            if uses_list:
                                _handle_uses_for_def(
                                    gdb, ser, test_data,
                                    def_addr_str, uses_list,
                                    coverage_mgr, input_gen
                                )

                            # Continue execution so we can see if any other def triggers
                            if def_bp_map:  # If there are still more def BPs left
                                gdb.continue_execution()

                        else:
                            logger.debug(f"Unknown breakpoint => {payload}, continuing.")
                            gdb.continue_execution()
                            # Possibly this means a leftover or invalid ID

                    elif reason == 'timed out':
                        logger.debug("No def triggered this attempt.")
                        no_trigger_count += 1  # increment because we got no triggers
                    elif reason in ('exited','crashed'):
                        logger.warning("Target crashed => restart.")
                        restart_program(gdb, ELF_PATH)
                        # Possibly record crash input
                        logger.warning(f"Target {reason}. Logging input and restarting.")
                        # Save the crashing input
                        crash_dir = os.path.join(OUTPUT_DIRECTORY, 'crashes')
                        os.makedirs(crash_dir, exist_ok=True)
                        crash_file = os.path.join(crash_dir, str(int(time.time())))
                        with open(crash_file, 'wb') as f:
                            f.write(test_data)
                        break
                    else:
                        logger.info(f"Unknown reason => {reason}, continuing.")
                        gdb.continue_execution()

                    # If we have no breakpoints left in def_bp_map => chunk is done
                    if not def_bp_map:
                        break

                # [NEW LOGIC FOR COVERAGE AFTER DEFS]
                timestamp = int(time.time())
                input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

                if coverage_mgr.check_new_coverage():
                    logger.info("New coverage found => add input to corpus.")
                    input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
                    input_gen.choose_new_baseline_input()

                # Cleanup at chunk completion. If some defs never triggered, we discard them
                # or keep them. For now let's remove them:
                force_halt_if_running(gdb)
                remaining_bp_ids = list(def_bp_map.keys())
                if remaining_bp_ids:
                    remove_breakpoints(gdb, remaining_bp_ids)
                    def_bp_map.clear()

                gdb.continue_execution()

                # If we had a triggered def or we exhausted tries, we've completed this chunk
                # => Move to next chunk or next round
                done_with_round = True

            coverage_mgr.reset_coverage()
            logger.info(f"End of round #{round_count}, coverage reset. Next pass.\n")

    except KeyboardInterrupt:
        logger.info("Stopped by user.")
    finally:
        ser.close()
        coverage_mgr.close()
        gdb.stop()
        logger.info("Clean exit from main().")


# [ADDED]
def _handle_uses_for_def(gdb, ser, test_data, def_addr_str, uses_list,
                         coverage_mgr, input_gen):
    logger.info(f"Handling uses for def={def_addr_str}. Found {len(uses_list)} uses.")
    uses_sorted = get_closest_uses(def_addr_str, uses_list)
    uses_idx = 0
    any_use_triggered = False

    while uses_idx < len(uses_sorted):
        uses_chunk = uses_sorted[uses_idx : uses_idx + HW_BREAKPOINT_LIMIT]
        uses_idx += HW_BREAKPOINT_LIMIT

        force_halt_if_running(gdb)
        # delete_all_breakpoints(gdb)
        #for now, there're 5 breakpoints set at defs, so we need to delete all the breakpoints after the def is triggered. and keep track back to the def after iterate all the uses. 

        uses_bp_map = {}
        for use_addr_str in uses_chunk:
            ubp_id = gdb.set_breakpoint(use_addr_str)
            uses_bp_map[ubp_id] = use_addr_str

        gdb.continue_execution()

        # We'll try until we run out of BPs or no triggers in a row
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
                    no_trigger_count = 0  # reset since something triggered
                else:
                    logger.info(f"Unknown breakpoint => continuing.",payload2)
                    gdb.continue_execution()

            elif reason2 == 'timed out':
                logger.info("No use triggered this attempt.")
                no_trigger_count += 1
            elif reason2 in ('exited','crashed'):
                logger.warning("Target crashed => restart.")
                restart_program(gdb, ELF_PATH)
                break
            else:
                logger.info(f"Unknown reason => {reason2}, continuing.")
                gdb.continue_execution()

        # coverage after finishing a chunk
        timestamp = int(time.time())
        input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

        if coverage_mgr.check_new_coverage():
            logger.info("New coverage from uses => add input to corpus.")
            input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
            input_gen.choose_new_baseline_input()

        force_halt_if_running(gdb)
        if uses_bp_map:
            remove_breakpoints(gdb, list(uses_bp_map.keys()))
            uses_bp_map.clear()
        logger.info("start continue")
        gdb.continue_execution()
        logger.info(f"End of use chunk, continuing to next chunk.")

    return any_use_triggered



if __name__ == '__main__':
    main()
