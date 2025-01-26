import os
import time
import random
import logging as log
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


##########################
# HELPER BREAKPOINT FUNCTIONS
##########################
def delete_all_breakpoints(gdb: GDB):
    log.debug("Deleting all existing breakpoints...")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        err = resp['payload'].get('msg', '')
        if 'No breakpoints to delete' not in err:
            raise Exception(f"Failed to delete breakpoints: {err}")
    else:
        log.info("Deleted all breakpoints.")

def force_halt_if_running(gdb: GDB, timeout=5):
    """
    If CPU is running, interrupt. If halted, skip. Then wait up to 'timeout' for a stop event.
    """
    resp = gdb.send('-data-list-register-values x', timeout=3)
    if resp['message'] == 'done':
        log.debug("CPU already halted; skipping re-halt.")
        return
    if resp['message'] == 'error':
        log.debug("Sending interrupt to force halt (CPU likely running).")
        gdb.interrupt()
        reason, payload = gdb.wait_for_stop(timeout=timeout)
        if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
            log.debug(f"CPU halted (reason='{reason}').")
        else:
            # Check again if halted
            resp2 = gdb.send('-data-list-register-values x', timeout=3)
            if resp2['message'] != 'done':
                raise Exception(f"Could not force halt (got reason='{reason}')")


def set_breakpoints_for_defs_randomly(gdb: GDB, all_defs, hw_breakpoints=6):
    """
    Randomly pick up to 'hw_breakpoints' definition addresses from `all_defs`,
    set breakpoints, and return {bkptno: (def_addr_str, uses_list)}.
    """
    force_halt_if_running(gdb)
    delete_all_breakpoints(gdb)

    chosen_defs = random.sample(all_defs, k=min(hw_breakpoints, len(all_defs)))
    defs_map = {}
    for def_addr_str, uses_list in chosen_defs:
        bkptno = gdb.set_breakpoint(def_addr_str)
        if bkptno is not None:
            defs_map[bkptno] = (def_addr_str, uses_list)

    log.info(f"Randomly set {len(defs_map)} definition breakpoints (up to {hw_breakpoints}).")
    # Let the CPU run again
    gdb.continue_execution()
    return defs_map


def set_breakpoints_for_uses_randomly(gdb: GDB, uses_list, hw_breakpoints=6):
    """
    Randomly pick up to 'hw_breakpoints' addresses from uses_list, set them,
    and return {bkptno: use_addr_str}.
    """
    force_halt_if_running(gdb)
    delete_all_breakpoints(gdb)

    chosen_uses = random.sample(uses_list, k=min(hw_breakpoints, len(uses_list)))
    uses_map = {}
    for use_addr_str in chosen_uses:
        bkptno = gdb.set_breakpoint(use_addr_str)
        if bkptno is not None:
            uses_map[bkptno] = use_addr_str

    log.info(f"Randomly set {len(uses_map)} use breakpoints (up to {hw_breakpoints}).")
    gdb.continue_execution()
    return uses_map


##########################
# RESTART PROGRAM HELPER
##########################
def restart_program(gdb: GDB, elf_path: str):
    """
    Force a full reset/halt, re-load ELF, break at main, run,
    then continue so the board re-initializes fully.
    """
    log.debug("Restarting program from scratch...")

    # If J-Link requires a digit, do: gdb.send('monitor reset 0')
    resp = gdb.send('monitor reset')
    log.debug(f"monitor reset => {resp}")
    resp = gdb.send('monitor halt')
    log.debug(f"monitor halt => {resp}")

    resp = gdb.send(f'-file-exec-and-symbols {elf_path}')
    log.debug(f"file-exec-and-symbols => {resp}")

    resp = gdb.send('-break-insert main')
    log.debug(f"-break-insert main => {resp}")

    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        log.warning("Could not run after restart; continuing instead.")
        gdb.continue_execution()

    reason, payload = gdb.wait_for_stop(timeout=10)
    if reason == 'timed out':
        raise Exception("Program did not halt at main after restart.")
    log.debug(f"Restart halted reason='{reason}'. Continuing tasks.")
    gdb.continue_execution()


##########################
# LOGGING SETUP
##########################
def setup_logging():
    logger = log.getLogger()
    logger.setLevel(LOG_LEVEL)

    formatter = log.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)

    ch = log.StreamHandler()
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


##########################
# MAIN FUNCTION
##########################
def main():
    test_case_count_since_last_trigger = 0

    # 1) Coverage
    coverage_mgr = CoverageManager()

    # 2) Initialize GDB
    gdb = GDB(
        gdb_path='gdb-multiarch',           # or your path to GDB
        gdb_server_address='localhost:2331',  # J-Link server
        software_breakpoint_addresses=[],
        consider_sw_breakpoint_as_error=False
    )

    logger.debug("Starting GDB setup...")
    elf_path = ELF_PATH
    gdb.connect(elf_path)

    # 3) One-time reset & halt
    logger.debug("Resetting & halting once at startup...")
    # For J-Link, if 'monitor reset' complains, do:
    # gdb.send('monitor reset 0')
    gdb.send('monitor reset')
    gdb.send('monitor halt')

    logger.debug(f"Loading ELF: {elf_path}")
    gdb.send(f'-file-exec-and-symbols {elf_path}')

    logger.debug("Inserting breakpoint at main & running it...")
    gdb.send('-break-insert main')
    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        logger.warning("Could not run the program. Attempting to continue instead...")
        gdb.continue_execution()

    reason, payload = gdb.wait_for_stop(timeout=10)
    if reason in ("breakpoint hit", "stopped, no reason given"):
        logger.debug("Stopped at main => continuing so tasks start up.")
        gdb.continue_execution()
    else:
        logger.warning(f"Unexpected reason for initial stop: {reason}")

    # 4) Parse definitions
    sorted_defs = parse_def_use_file(DEF_USE_FILE)
    if not sorted_defs:
        logger.error("No definitions found in def_use file.")
        return

    # 5) Place random definition breakpoints
    defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)

    # 6) Setup serial
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
    time.sleep(2)  # small stabilization

    # 7) Setup input generation
    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
    )

    # Let the CPU run after setting def breakpoints
    gdb.continue_execution()

    try:
        # Generate the first test
        input_gen.choose_new_baseline_input()
        test_case_bytes = input_gen.generate_input()

        # 8) Fuzz loop
        while True:
            logger.info("--------------------------------")
            coverage_mgr.reset_coverage()

            # Send test to SUT
            logger.info("Sending test case to the board via serial.")
            response = send_test_case(ser, test_case_bytes)
            process_response(response)

            # Wait for GDB event
            reason, payload = gdb.wait_for_stop(timeout=4)
            logger.info(f"Received event: {reason}, payload: {payload}")

            if reason == 'breakpoint hit':
                bkptno = payload
                logger.info(f"Breakpoint hit => {bkptno}")
                test_case_count_since_last_trigger = 0

                if bkptno in defs_map:
                    # We have a definition BP
                    def_addr_str, uses_list = defs_map[bkptno]
                    coverage_mgr.update_coverage_for_def(def_addr_str)
                    logger.info(f"Definition coverage updated => {def_addr_str}")

                    # Set uses
                    uses_map = set_breakpoints_for_uses_randomly(
                        gdb, uses_list, hw_breakpoints=6
                    )
                    # Wait for use event
                    reason2, payload2 = gdb.wait_for_stop(timeout=5)
                    if reason2 == 'breakpoint hit':
                        logger.info(f"Use breakpoint hit => {payload2}")
                        if payload2 in uses_map:
                            use_addr_str = uses_map[payload2]
                            coverage_mgr.update_coverage_for_defuse(def_addr_str, use_addr_str)
                            logger.info(f"Def-use coverage updated => {def_addr_str},{use_addr_str}")

                    # Revert to definitions again
                    defs_map = set_breakpoints_for_defs_randomly(
                        gdb, sorted_defs, hw_breakpoints=6
                    )
                    gdb.continue_execution()

                else:
                    # Possibly a "use" or unknown BP
                    logger.info(f"Unknown or use breakpoint => {bkptno}")
                    # If you want coverage for direct uses:
                    # if bkptno in uses_map: coverage_mgr.update_coverage_for_defuse(...)
                    gdb.continue_execution()

            elif reason == 'timed out':
                logger.info("No breakpoints triggered by this test case.")
                test_case_count_since_last_trigger += 1
                if test_case_count_since_last_trigger > NO_TRIGGER_THRESHOLD:
                    logger.info("No triggers for too long => re-random definitions.")
                    defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
                    test_case_count_since_last_trigger = 0

            elif reason in ('exited','crashed'):
                logger.warning(f"Target {reason}. Logging input & restarting.")
                # Save crashing input
                crash_dir = os.path.join(OUTPUT_DIRECTORY, 'crashes')
                os.makedirs(crash_dir, exist_ok=True)
                crash_file = os.path.join(crash_dir, str(int(time.time())))
                with open(crash_file, 'wb') as f:
                    f.write(test_case_bytes)

                # Restart program
                restart_program(gdb, elf_path)
                defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
                gdb.continue_execution()

            # Coverage check (dummy example at address=0)
            timestamp = int(time.time())
            input_gen.report_address_reached(test_case_bytes, address=0, timestamp=timestamp)

            if coverage_mgr.check_new_coverage():
                log.info("New coverage found => add input to corpus.")
                input_gen.add_corpus_entry(test_case_bytes, address=0, timestamp=timestamp)

            # Generate next input
            # input_gen.choose_new_baseline_input()
            # test_case_bytes = input_gen.generate_input()

            time.sleep(0.1)

    except KeyboardInterrupt:
        logger.info("Stopping fuzzing due to KeyboardInterrupt.")
    finally:
        ser.close()
        coverage_mgr.close()
        gdb.stop()


if __name__ == '__main__':
    main()
