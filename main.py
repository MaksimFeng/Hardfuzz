import os
import time
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
from fuzzing.input_generation import InputGeneration
from fuzzing.gdb_interface import GDB
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

    try:
        # '-data-list-register-values x' returns register values in hex.
        # If the target is halted and responsive, it should get a "done" response
        # with register values. If it's running or inaccessible, we may get an error or timeout.
        resp = gdb.send('-data-list-register-values x', timeout=timeout)
        if resp['message'] == 'done' and 'payload' in resp:
            registers = resp['payload'].get('register-values', [])
            # If have some register values, assume target is accessible/halted
            if len(registers) > 0:
                return True
        return False
    except TimeoutError:
        # If timed out, target not accessible.
        return False
    except Exception as e:
        return False


def halt_target(gdb: GDB, max_retries=3, elf_path=ELF_PATH):
    for attempt in range(max_retries):
        logger.debug("Halting target...")
        gdb.interrupt()
        reason, payload = gdb.wait_for_stop(timeout=5)
        if reason == 'timed out':
            logger.warning("Interrupt timed out, trying 'monitor halt'...")
            gdb.send('monitor halt')
            # Don't always rely on a new event:
            # Check if the target is accessible or assume halted.
            if target_is_accessible(gdb):
                logger.debug("Target seems halted (no new event, but registers accessible).")
                return
            else:
                logger.warning(f"Halt attempt {attempt+1} timed out, retrying...")
                continue
        else:
            # If we got a reason or 'exited', handle accordingly
            if reason == 'exited':
                logger.warning("Program exited while halting. Restarting program...")
                gdb.restart_program(elf_path)
            else:
                logger.debug(f"Target halted with reason: {reason}")
            return
    raise Exception("Could not halt the target after multiple attempts.")

def delete_all_breakpoints(gdb: GDB):
    """Delete all existing breakpoints while target is halted."""
    logger.debug("Deleting all existing breakpoints...")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        # It's possible there were no breakpoints to delete or another error occurred
        error_msg = resp['payload'].get('msg', '')
        if 'No breakpoints to delete' not in error_msg:
            raise Exception(f"Failed to delete breakpoints: {error_msg}")
    else:
        logger.info("Deleted all breakpoints.")

def set_breakpoints_for_defs(gdb: GDB, defs_group):
    """Set breakpoints at definition addresses from a defs_group."""
    
    halt_target(gdb)
    logger.info("Deleting all existing breakpoints...")
    delete_all_breakpoints(gdb)

    defs_map = {}
    # Limit to first 3 definitions for now, similar to the original code
    for i, (def_addr, uses) in enumerate(defs_group[:3]):
        bkptno = gdb.set_breakpoint(def_addr)
        if bkptno is not None:
            defs_map[bkptno] = (def_addr, uses)
    logger.info(f"Set breakpoints for {len(defs_map)} definitions.")
    logger.info(f"Defs map is: {defs_map}")
    return defs_map

def set_breakpoints_for_uses(gdb: GDB, uses):
    """Set breakpoints at use addresses for a given definition."""
    halt_target(gdb)
    delete_all_breakpoints(gdb)
    uses_map = {}
    # Limit to first 3 uses
    #change to random 3
    for use_addr in uses[:3]:
        bkptno = gdb.set_breakpoint(use_addr)
        if bkptno is not None:
            uses_map[bkptno] = use_addr
    return uses_map

def main():
    # After NO_TRIGGER_THRESHOLD consecutive test cases without any breakpoint hit,
    # move to the next group of definitions.
    test_case_count_since_last_trigger = 0
    current_group_index = 0

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

    sorted_defs = parse_def_use_file(DEF_USE_FILE)
    defs_in_groups = [sorted_defs[i:i+3] for i in range(0, len(sorted_defs), 3)]
    if not defs_in_groups:
        logger.error("No definitions found in def_use file.")
        return

    # Set initial breakpoints for the first defs group
    defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
    mode = 'definition'

    # Setup serial
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
    time.sleep(2)  # Give time for serial to stabilize

    # Setup input generation
    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
    )

    # Continue execution after setting initial breakpoints
    gdb.continue_execution()

    try:
        while True:
            # Generate a new input
            input_gen.choose_new_baseline_input()
            test_case_bytes = input_gen.generate_input()

            # Send test case to SUT via serial
            response = send_test_case(ser, test_case_bytes)
            process_response(response)

            # Wait for an event: breakpoint hit, crash, or timeout
            reason, payload = gdb.wait_for_stop(timeout=2)

            event_happened = False

            if reason == 'breakpoint hit':
                event_happened = True
                test_case_count_since_last_trigger = 0
                bkptno = payload

                # Halt target to safely manipulate breakpoints
                halt_target(gdb)

                if bkptno in defs_map:
                    # A definition breakpoint triggered
                    def_addr, uses = defs_map[bkptno]
                    logger.info(f"Breakpoint triggered at def {hex(def_addr)}, setting breakpoints at its uses.")
                    uses_map = set_breakpoints_for_uses(gdb, uses)

                    # After setting uses breakpoints, continue and wait
                    gdb.continue_execution()
                    reason2, payload2 = gdb.wait_for_stop(timeout=5)
                    if reason2 == 'breakpoint hit':
                        logger.info(f"Breakpoint hit at use {hex(payload2)}.")
                        # Here you could handle coverage, logging, etc.

                    # After handling uses breakpoints, restore definition breakpoints again if needed
                    defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
                    gdb.continue_execution()

                else:
                    # Hit some other breakpoint (e.g., uses)
                    logger.info(f"Breakpoint hit at {hex(payload)}")
                    #keep one testcase
                    #how many execution needed for hit defs
                    #and hit the uses
                    gdb.continue_execution()

            elif reason == 'timed out':
                # No event (no breakpoints triggered)
                # gdb.send('monitor reset halt')
                # halt_target(gdb)
                logger.info("No breakpoints triggered by this test case.")
                test_case_count_since_last_trigger += 1
                if test_case_count_since_last_trigger > NO_TRIGGER_THRESHOLD:
                    current_group_index += 1
                    if current_group_index < len(defs_in_groups):
                        logger.info(f"Moving to next definition group index {current_group_index}.")
                        defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
                        
                        test_case_count_since_last_trigger = 0
                        gdb.continue_execution()
                    else:
                        logger.info("No more definition groups to try. Exiting.")
                        break
                else:
                    gdb.continue_execution()

            elif reason == 'exited' or reason == 'crashed':
                # Handle crashes similar to the GDBFuzzer approach
                logger.warning(f"Target {reason}. Logging input and restarting.")
                # Save the crashing input
                crash_dir = os.path.join(OUTPUT_DIRECTORY, 'crashes')
                os.makedirs(crash_dir, exist_ok=True)
                crash_file = os.path.join(crash_dir, str(int(time.time())))
                with open(crash_file, 'wb') as f:
                    f.write(test_case_bytes)

                gdb.restart_program(elf_path)
                defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
                gdb.continue_execution()

            # Report coverage for demonstration (address=0 is just an example)
            timestamp = int(time.time())
            input_gen.report_address_reached(test_case_bytes, address=0, timestamp=timestamp)

            time.sleep(0.1)

    except KeyboardInterrupt:
        logger.info("Stopping fuzzing due to KeyboardInterrupt.")
    finally:
        ser.close()
        gdb.stop()


if __name__ == '__main__':
    main()
