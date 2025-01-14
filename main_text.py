import os
import time
import random
import logging as log
import multiprocessing as mp
import serial
import logging.handlers

from config.settings import (
    LOG_LEVEL, LOG_FORMAT, LOG_DATEFMT, LOG_FILE,
    SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
    OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
    NO_TRIGGER_THRESHOLD
)

# Import your GDB class from gdb_interface.py
from fuzzing.gdb_interface import GDB

# These are placeholders for your real modules:
from fuzzing.input_generation import InputGeneration
from communication.serial_comm import send_test_case, process_response
from utils.file_parsing import parse_def_use_file


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


def target_is_accessible(gdb: GDB, timeout: int = 5) -> bool:
    """Check if target is halted and accessible by requesting register values."""
    try:
        resp = gdb.send('-data-list-register-values x', timeout=timeout)
        if resp['message'] == 'done' and 'payload' in resp:
            registers = resp['payload'].get('register-values', [])
            if len(registers) > 0:
                return True
        return False
    except (TimeoutError, Exception):
        return False


def halt_target(gdb: GDB, max_retries=3, elf_path=ELF_PATH):
    """
    Attempt to halt the target by sending an interrupt and, if that fails,
    do 'monitor halt'. If the target has exited, restart the program.
    """
    for attempt in range(max_retries):
        logger.debug("Halting target...")
        gdb.interrupt()
        reason, payload = gdb.wait_for_stop(timeout=5)
        if reason == 'timed out':
            logger.warning("Interrupt timed out, trying 'monitor halt'...")
            gdb.send('monitor halt')
            if target_is_accessible(gdb):
                logger.debug("Target seems halted (registers accessible).")
                return
            else:
                logger.warning(f"Halt attempt {attempt+1} timed out, retrying...")
                continue
        else:
            if reason == 'exited':
                logger.warning("Program exited while halting. Restarting program...")
                gdb.restart_program(elf_path)
            else:
                logger.debug(f"Target halted with reason: {reason}")
            return
    raise Exception("Could not halt the target after multiple attempts.")


def delete_all_breakpoints(gdb: GDB):
    """Delete all existing breakpoints (definition or use) while target is halted."""
    logger.debug("Deleting all existing breakpoints...")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        error_msg = resp['payload'].get('msg', '')
        if 'No breakpoints to delete' not in error_msg:
            raise Exception(f"Failed to delete breakpoints: {error_msg}")
    else:
        logger.info("Deleted all breakpoints.")


def set_breakpoints_for_defs_randomly(gdb: GDB, all_defs, hw_breakpoints=6):
    """
    Randomly select up to 'hw_breakpoints' definitions from `all_defs`
    and set breakpoints for them. We assume we have EXACTLY 6 hardware breakpoints
    to use, so we set up to 6 definition breakpoints in one go.

    :param all_defs: list of (def_addr_str, uses_list) tuples
    :param hw_breakpoints: how many breakpoints we want to set (6).
    :return: dict: bkptno -> (def_addr_str, uses_list)
    """
    halt_target(gdb)
    delete_all_breakpoints(gdb)

    # In case you have fewer than 6 definitions total, take as many as exist.
    chosen_defs = random.sample(all_defs, k=min(hw_breakpoints, len(all_defs)))

    defs_map = {}
    for (def_addr_str, uses_list) in chosen_defs:
        bkptno = gdb.set_breakpoint(def_addr_str)
        if bkptno is not None:
            defs_map[bkptno] = (def_addr_str, uses_list)

    logger.info(f"Randomly set {len(defs_map)} definition breakpoints (up to 6).")
    return defs_map


def set_breakpoints_for_uses_randomly(gdb: GDB, uses_list, hw_breakpoints=6):
    """
    Randomly select up to 'hw_breakpoints' addresses from uses_list and
    set breakpoints for them. We assume we can use all 6 hardware breakpoints
    for uses as well. We remove the old breakpoints first.

    :param uses_list: list of address strings for the uses
    :param hw_breakpoints: number of hardware breakpoints to set (6)
    :return: dict: bkptno -> use_addr_str
    """
    halt_target(gdb)
    delete_all_breakpoints(gdb)

    chosen_uses = random.sample(uses_list, k=min(hw_breakpoints, len(uses_list)))

    uses_map = {}
    for use_addr_str in chosen_uses:
        bkptno = gdb.set_breakpoint(use_addr_str)
        if bkptno is not None:
            uses_map[bkptno] = use_addr_str

    logger.info(f"Randomly set {len(uses_map)} use breakpoints (up to 6).")
    return uses_map


def main():
    test_case_count_since_last_trigger = 0

    # Initialize GDB
    gdb = GDB(
        gdb_path='gdb-multiarch',
        gdb_server_address='localhost:2331',
        software_breakpoint_addresses=[],
        consider_sw_breakpoint_as_error=False
    )

    logger.debug("Starting GDB setup...")
    elf_path = ELF_PATH
    gdb.connect(elf_path)

    # Reset and halt the target
    logger.debug("Resetting and halting the target...")
    gdb.send('monitor reset halt')

    # Load ELF and symbols
    logger.debug(f"Loading ELF: {elf_path}")
    gdb.send(f'-file-exec-and-symbols {elf_path}')

    # Insert breakpoint at main and run
    logger.debug("Inserting breakpoint at main...")
    gdb.send('-break-insert main')

    logger.debug("Running the program...")
    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        logger.warning("Could not run the program. Attempting to continue instead...")
        gdb.continue_execution()

    # Wait for a stop event at main
    reason, payload = gdb.wait_for_stop(timeout=10)
    if reason == 'timed out':
        logger.warning("No stop event after running. Trying to halt manually.")
        halt_target(gdb)

    # Parse definitions and uses from def_use file
    sorted_defs = parse_def_use_file(DEF_USE_FILE)
    if not sorted_defs:
        logger.error("No definitions found in def_use file.")
        return

    # Randomly set up to 6 definition breakpoints
    defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)

    # Setup serial
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
    time.sleep(2)  # Give time for serial to stabilize

    # Setup input generation
    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
    )

    # Continue after setting breakpoints
    gdb.continue_execution()

    try:
        # Pre-generate the first test input
        input_gen.choose_new_baseline_input()
        test_case_bytes = input_gen.generate_input()

        while True:
            # Send test case to SUT via serial
            response = send_test_case(ser, test_case_bytes)
            process_response(response)

            # Wait for an event
            reason, payload = gdb.wait_for_stop(timeout=2)
            logger.info(f"Received event: {reason}, payload: {payload}")

            if reason == 'breakpoint hit':
                test_case_count_since_last_trigger = 0
                bkptno = payload

                # Halt the target safely
                halt_target(gdb)

                if bkptno in defs_map:
                    # hit one of the definition breakpoints
                    def_addr_str, uses_list = defs_map[bkptno]
                    logger.info(f"Definition breakpoint hit: address {def_addr_str} (bkptno={bkptno}).")

                    # Now set up to 6 random breakpoints for the uses
                    uses_map = set_breakpoints_for_uses_randomly(gdb, uses_list, hw_breakpoints=6)
                    gdb.continue_execution()

                    # Wait to see if a use is hit
                    reason2, payload2 = gdb.wait_for_stop(timeout=5)
                    if reason2 == 'breakpoint hit':
                        logger.info(f"Use breakpoint hit: address {payload2} (for def={def_addr_str}).")
                        # Handle coverage / logging if needed

                    # After uses, revert back to definitions again
                    defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
                    gdb.continue_execution()
                else:
                    # We likely hit a "use" breakpoint or something else.
                    logger.info(f"Hit a 'use' or unknown breakpoint (bkptno={bkptno}).")
                    gdb.continue_execution()

            elif reason == 'timed out':
                logger.info("No breakpoints triggered by this test case.")
                test_case_count_since_last_trigger += 1
                if test_case_count_since_last_trigger > NO_TRIGGER_THRESHOLD:
                    logger.info("No triggers for too long. Resetting definitions randomly.")
                    defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
                    test_case_count_since_last_trigger = 0
                # else:
                #     # Just continue if the target is still running
                #     gdb.continue_execution()

            elif reason in ('exited', 'crashed'):
                logger.warning(f"Target {reason}. Logging input and restarting.")
                # Save the crashing input
                crash_dir = os.path.join(OUTPUT_DIRECTORY, 'crashes')
                os.makedirs(crash_dir, exist_ok=True)
                crash_file = os.path.join(crash_dir, str(int(time.time())))
                with open(crash_file, 'wb') as f:
                    f.write(test_case_bytes)

                # Restart program
                gdb.restart_program(elf_path)
                defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
                gdb.continue_execution()

            # Example coverage tracking (address=0 is a dummy example)
            timestamp = int(time.time())
            input_gen.report_address_reached(test_case_bytes, address=0, timestamp=timestamp)

            # # Generate next input
            # input_gen.choose_new_baseline_input()
            # test_case_bytes = input_gen.generate_input()

            time.sleep(0.1)

    except KeyboardInterrupt:
        logger.info("Stopping fuzzing due to KeyboardInterrupt.")
    finally:
        ser.close()
        gdb.stop()


if __name__ == '__main__':
    main()
