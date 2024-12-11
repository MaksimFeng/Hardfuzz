import os
import time
import logging as log
import multiprocessing as mp

import serial

from config.settings import (
    LOG_LEVEL, LOG_FORMAT, SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
    OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
    NO_TRIGGER_THRESHOLD
)
from fuzzing.input_generation import InputGeneration
from fuzzing.gdb_interface import GDB
from communication.serial_comm import send_test_case, process_response
from utils.file_parsing import parse_def_use_file

# Configure logging
log.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

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
    elf_path = ELF_PATH
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

    sorted_defs = parse_def_use_file(DEF_USE_FILE)
    defs_in_groups = [sorted_defs[i:i+3] for i in range(0, len(sorted_defs), 3)]
    if not defs_in_groups:
        log.error("No definitions found in def_use file.")
        return

    # Now that target is halted (hit main or manually halted), set initial breakpoints
    defs_map = set_breakpoints_for_defs(gdb, defs_in_groups[current_group_index])
    mode = 'breakpoint'

    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
    time.sleep(2)

    input_gen = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=1024
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
                if test_case_count_since_last_trigger > NO_TRIGGER_THRESHOLD:
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
