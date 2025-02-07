# import os
# import time
# import random
# import logging as log
# import logging.handlers
# import serial

# from fuzzing.coverage_manager import CoverageManager
# from config.settings import (
#     LOG_LEVEL, LOG_FORMAT, LOG_DATEFMT, LOG_FILE,
#     SERIAL_PORT, BAUD_RATE, SERIAL_TIMEOUT,
#     OUTPUT_DIRECTORY, SEEDS_DIRECTORY, ELF_PATH, DEF_USE_FILE,
#     NO_TRIGGER_THRESHOLD
# )
# from fuzzing.gdb_interface import GDB
# from fuzzing.input_generation import InputGeneration
# from communication.serial_comm import send_test_case, process_response
# from utils.file_parsing import parse_def_use_file


# ##########################
# # HELPER BREAKPOINT FUNCTIONS
# ##########################
# def delete_all_breakpoints(gdb: GDB):
#     log.debug("Deleting all existing breakpoints...")
#     resp = gdb.send('-break-delete')
#     if resp['message'] == 'error':
#         err = resp['payload'].get('msg', '')
#         if 'No breakpoints to delete' not in err:
#             raise Exception(f"Failed to delete breakpoints: {err}")
#     else:
#         log.info("Deleted all breakpoints.")

# def force_halt_if_running(gdb: GDB, max_attempts=3, wait_timeout=5):
#     """
#     Safely ensure the CPU is fully halted.
#     Repeatedly:
#       1) Try reading registers with `-data-list-register-values`.
#       2) If 'error' => do gdb.interrupt() => read events => check again.
#       3) If 'done' => CPU is halted => return.
#     """
#     for attempt in range(max_attempts):
#         resp = gdb.send('-data-list-register-values x', timeout=3)
#         if resp['message'] == 'done':
#             log.debug("CPU is halted (data-list-register-values => done).")
#             return  # success
#         else:
#             log.debug("CPU not halted => sending interrupt.")
#             gdb.interrupt()
#             # Drain all stop events until we see one that indicates total halt.
#             while True:
#                 reason, payload = gdb.wait_for_stop(timeout=wait_timeout)
#                 if reason == 'timed out':
#                     log.debug("No further stop events => break loop & recheck registers.")
#                     break
#                 if reason in ('breakpoint hit','interrupt','exited','crashed','stopped, no reason given'):
#                     log.debug(f"Got a stop reason={reason}, CPU likely halted now. Recheck registers.")
#                     break
#             resp2 = gdb.send('-data-list-register-values x', timeout=3)
#             if resp2['message'] == 'done':
#                 log.debug("CPU is halted on second try.")
#                 return
#     # If we exit the loop => still not 'done'? 
#     # Raise an error to avoid infinite loops
#     raise Exception("Could not force CPU to a fully halted state after multiple attempts.")



# def set_breakpoints_for_defs_randomly(gdb: GDB, all_defs, hw_breakpoints=6):
#     """
#     Randomly pick up to 'hw_breakpoints' definition addresses from `all_defs`,
#     set breakpoints, and return {bkptno: (def_addr_str, uses_list)}.
#     """
#     force_halt_if_running(gdb)
#     delete_all_breakpoints(gdb)

#     chosen_defs = random.sample(all_defs, k=min(hw_breakpoints, len(all_defs)))
#     defs_map = {}
#     for def_addr_str, uses_list in chosen_defs:
#         bkptno = gdb.set_breakpoint(def_addr_str)
#         if bkptno is not None:
#             defs_map[bkptno] = (def_addr_str, uses_list)

#     log.info(f"Randomly set {len(defs_map)} definition breakpoints (up to {hw_breakpoints}).")
#     # Let the CPU run again
#     gdb.continue_execution()
#     return defs_map


# def set_breakpoints_for_defs_weighted(gdb: GDB, all_defs, hw_breakpoints=6):
#     """
#         Definitions with more uses are more likely to be chosen, but not guaranteed every time.
#     """
#     force_halt_if_running(gdb)
#     delete_all_breakpoints(gdb)

#     sorted_by_uses = sorted(all_defs, key=lambda x: len(x[1]), reverse=True)

#     weighted_defs = []
#     for def_addr_str, uses_list in sorted_by_uses:
#         w = float(len(uses_list))
#         weighted_defs.append((def_addr_str, uses_list, w))

#     total_weight = sum(w for _, _, w in weighted_defs)
#     if total_weight == 0:
#         chosen = random.sample(sorted_by_uses, k=min(hw_breakpoints, len(sorted_by_uses)))
#     else:
#         chosen = []
#         temp_list = weighted_defs[:]

#         for _ in range(hw_breakpoints):
#             if not temp_list:
#                 break
#             # Pick a random float up to total_weight
#             r = random.random() * total_weight
#             cumulative = 0.0
#             for idx, (def_str, uses_list, w) in enumerate(temp_list):
#                 cumulative += w
#                 if cumulative >= r:
#                     chosen.append((def_str, uses_list))
#                     # Remove it so don't pick it again
#                     total_weight -= w
#                     del temp_list[idx]
#                     break

#     defs_map = {}
#     for def_addr_str, uses_list in chosen:
#         bkptno = gdb.set_breakpoint(def_addr_str)
#         if bkptno is not None:
#             defs_map[bkptno] = (def_addr_str, uses_list)

#     log.info(f"Weighted random (defs): set {len(defs_map)} definition breakpoints.")
#     gdb.continue_execution()
#     return defs_map

# def set_breakpoints_for_closest_uses(gdb: GDB, def_addr_str, uses_list, hw_breakpoints=1):
#     """
#     hardware breakpoints on the *uses* that are closer to `def_addr_str`.
#     Closer uses have higher weight, but there's still randomness.
#     """
#     force_halt_if_running(gdb)
#     delete_all_breakpoints(gdb)

#     def_addr = int(def_addr_str, 16)

#     # Build (use_addr_str, distance, weight)
#     weighted_uses = []
#     for use_addr_str in uses_list:
#         dist = abs(int(use_addr_str, 16) - def_addr)
#         # The +1 avoids division by zero and ensures a non-infinite weight
#         weight = 1.0 / (dist + 1.0)
#         weighted_uses.append((use_addr_str, dist, weight))

#     total_weight = sum(w for _, _, w in weighted_uses)
#     if total_weight == 0:
#         # If something is off (e.g. no uses, or all dist=0?), just random sample
#         chosen_uses = random.sample(uses_list, k=min(hw_breakpoints, len(uses_list)))
#     else:
#         chosen_uses = []
#         temp_list = weighted_uses[:]

#         # No-replacement weighted picking up to hw_breakpoints
#         for _ in range(hw_breakpoints):
#             if not temp_list:
#                 break
#             r = random.random() * total_weight
#             cumulative = 0.0
#             for idx, (use_addr, dist, w) in enumerate(temp_list):
#                 cumulative += w
#                 if cumulative >= r:
#                     chosen_uses.append(use_addr)
#                     total_weight -= w
#                     del temp_list[idx]
#                     break

#     # Actually set the breakpoints for the chosen uses
#     uses_map = {}
#     for use_addr_str in chosen_uses:
#         bkptno = gdb.set_breakpoint(use_addr_str)
#         if bkptno is not None:
#             uses_map[bkptno] = use_addr_str

#     log.info(f"Set {len(uses_map)} use breakpoints near def={def_addr_str} (weighted random by distance).")
#     gdb.continue_execution()
#     return uses_map


# def set_breakpoints_for_uses_randomly(gdb: GDB, uses_list, hw_breakpoints=1):
#     """
#     Randomly pick up to 'hw_breakpoints' addresses from uses_list, set them,
#     and return {bkptno: use_addr_str}.
#     """
#     force_halt_if_running(gdb)
#     delete_all_breakpoints(gdb)

#     chosen_uses = random.sample(uses_list, k=min(hw_breakpoints, len(uses_list)))
#     uses_map = {}
#     for use_addr_str in chosen_uses:
#         bkptno = gdb.set_breakpoint(use_addr_str)
#         if bkptno is not None:
#             uses_map[bkptno] = use_addr_str

#     log.info(f"Randomly set {len(uses_map)} use breakpoints (up to {hw_breakpoints}).")
#     gdb.continue_execution()
#     return uses_map


# ##########################
# # RESTART PROGRAM HELPER
# ##########################
# def restart_program(gdb: GDB, elf_path: str):
#     """
#     Force a full reset/halt, re-load ELF, break at main, run,
#     then continue so the board re-initializes fully.
#     """
#     log.debug("Restarting program from scratch...")

#     # If J-Link requires a digit, do: gdb.send('monitor reset 0')
#     resp = gdb.send('monitor reset halt')
#     log.debug(f"monitor reset => {resp}")
#     # resp = gdb.send('monitor halt')
#     log.debug(f"monitor halt => {resp}")

#     resp = gdb.send(f'-file-exec-and-symbols {elf_path}')
#     log.debug(f"file-exec-and-symbols => {resp}")

#     resp = gdb.send('-break-insert main')
#     log.debug(f"-break-insert main => {resp}")

#     run_resp = gdb.send('-exec-run')
#     if run_resp['message'] == 'error':
#         log.warning("Could not run after restart; continuing instead.")
#         gdb.continue_execution()

#     reason, payload = gdb.wait_for_stop(timeout=10)
#     if reason == 'timed out':
#         raise Exception("Program did not halt at main after restart.")
#     log.debug(f"Restart halted reason='{reason}'. Continuing tasks.")
#     gdb.continue_execution()


# ##########################
# # LOGGING SETUP
# ##########################
# def setup_logging():
#     logger = log.getLogger()
#     logger.setLevel(LOG_LEVEL)

#     formatter = log.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)

#     ch = log.StreamHandler()
#     ch.setLevel(LOG_LEVEL)
#     ch.setFormatter(formatter)
#     logger.addHandler(ch)

#     fh = logging.handlers.RotatingFileHandler(
#         LOG_FILE, maxBytes=10*1024*1024, backupCount=5
#     )
#     fh.setLevel(LOG_LEVEL)
#     fh.setFormatter(formatter)
#     logger.addHandler(fh)

#     return logger

# logger = setup_logging()

# ##########################
# # testing
# ##########################

# def set_named_breakpoint(gdb:GDB, func_name: str) -> str:
#     """
#     Insert a breakpoint at a named function or symbol (e.g. 'parser', 'loop', 'main').
#     Returns the breakpoint number string (e.g. '1', '2', etc.).
#     Raises Exception if unsuccessful.
#     """
#     force_halt_if_running(gdb)
#     delete_all_breakpoints(gdb)
#     logger.info(f"Inserting breakpoint at function: {func_name}")
#     resp = gdb.send(f'-break-insert {func_name}')
#     if resp['message'] != 'done':
#         raise Exception(f"Failed to insert breakpoint at function: {func_name}")
#     bp_id = resp['payload']['bkpt']['number']
#     logger.info(f"Breakpoint inserted at function: {func_name}, id: {bp_id}")
#     return bp_id

# ##########################
# # MAIN FUNCTION
# ##########################
# def main():
#     test_case_count_since_last_trigger = 0

#     # 1) Coverage
#     coverage_mgr = CoverageManager()

#     # 2) Initialize GDB
#     gdb = GDB(
#         gdb_path='gdb-multiarch',           
#         gdb_server_address='localhost:2331',  # J-Link server
#         software_breakpoint_addresses=[],
#         consider_sw_breakpoint_as_error=False
#     )

#     logger.debug("Starting GDB setup...")
#     elf_path = ELF_PATH
#     gdb.connect(elf_path)

#     # 3) One-time reset & halt
#     logger.debug("Resetting & halting once at startup...")
#     # For J-Link maybe also could try do:
#     # gdb.send('monitor reset 0')
#     gdb.send('monitor reset halt')
#     # gdb.send('monitor halt')

#     logger.debug(f"Loading ELF: {elf_path}")
#     gdb.send(f'-file-exec-and-symbols {elf_path}')

#     logger.debug("Inserting breakpoint at main & running it...")
#     gdb.send('-break-insert main')
#     run_resp = gdb.send('-exec-run')
#     if run_resp['message'] == 'error':
#         logger.warning("Could not run the program. Attempting to continue instead...")
#         gdb.continue_execution()

#     reason, payload = gdb.wait_for_stop(timeout=10)
#     logger.info(f"Initial stop reason: {reason}, payload: {payload}")
#     if reason in ("breakpoint hit", "stopped, no reason given"):
#         logger.debug(f"Stopped at main => continuing so tasks start up.{reason}")
#         gdb.continue_execution()
#     else:
#         logger.warning(f"Unexpected reason for initial stop: {reason}")

#     #### for testing
  
#     # parser_bkptno = set_named_breakpoint(gdb, 'parser')
#     # reason2, payload2 = gdb.wait_for_stop(timeout=10)
#     # logger.info(f"Second parser reason: {reason2}, payload: {payload2}")
#     # if reason2 in ("breakpoint hit", "stopped, no reason given"):
#     #     logger.debug(f"{payload2}Stopped at parser => continuing so tasks start up. {reason2}")
#     #     gdb.continue_execution()
#     # else:
#     #     logger.warning(f"Unexpected reason for second stop: {reason2}")
#     # gdb.continue_execution()
#     #######################


#     # temporary comment the def-use file parsing for testing
#     # 4) Parse definitions
#     sorted_defs = parse_def_use_file(DEF_USE_FILE)
#     if not sorted_defs:
#         logger.error("No definitions found in def_use file.")
#         return

#     # 5) Place random definition breakpoints
#     # defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
#     defs_map = set_breakpoints_for_defs_weighted(gdb, sorted_defs, hw_breakpoints=6)
#     # 6) Setup serial
#     ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=SERIAL_TIMEOUT)
#     time.sleep(2)  # small stabilization

#     # 7) Setup input generation
#     input_gen = InputGeneration(
#         output_directory=OUTPUT_DIRECTORY,
#         seeds_directory=SEEDS_DIRECTORY,
#         max_input_length=1024
#     )

#     # Let the CPU run after setting def breakpoints
#     gdb.continue_execution()

#     ####testing test case
#     test_case_bytes = b'{"test":123}'

#     try:
#         # Generate the first test
#         ############################for testing comment this two line
#         input_gen.choose_new_baseline_input()
#         test_case_bytes = input_gen.generate_input()

#         # 8) Fuzz loop
#         while True:
#             logger.info("--------------------------------")
#             coverage_mgr.reset_coverage()

#             # Send test to SUT
#             logger.info("Sending test case to the board via serial.")
#             response = send_test_case(ser, test_case_bytes)
#             process_response(response)

#             # Wait for GDB event
#             reason, payload = gdb.wait_for_stop(timeout=4)
#             logger.info(f"Received event: {reason}, payload: {payload}")

#             # if reason == 'breakpoint hit':
#             if reason in ("breakpoint hit", "stopped, no reason given"):
#                 bkptno = payload
#                 logger.info(f"Breakpoint hit => {bkptno}")
#                 test_case_count_since_last_trigger = 0

#                 ##### for testing
#                 # if payload == parser_bkptno:
#                 #     logger.info("parser() breakpoint was hit! GDB is working.")
#                 #     logger.info("_______________________________")
#                 # else:
#                 #     logger.info(f"Hit some other BP: {payload}")
#                 # gdb.continue_execution()


#                 if bkptno in defs_map:
#                     # We have a definition BP
#                     def_addr_str, uses_list = defs_map[bkptno]
#                     coverage_mgr.update_coverage_for_def(def_addr_str)
#                     logger.info(f"Definition coverage updated => {def_addr_str}")

#                     # Set uses
#                     # uses_map = set_breakpoints_for_uses_randomly(
#                         # gdb, uses_list, hw_breakpoints=6
#                     # )
#                     uses_map = set_breakpoints_for_closest_uses(
#                         gdb, def_addr_str, uses_list, hw_breakpoints=6
#                     )
#                     # Wait for use event
#                     reason2, payload2 = gdb.wait_for_stop(timeout=5)
#                     if reason2 == 'breakpoint hit':
#                         logger.info(f"Use breakpoint hit => {payload2}")
#                         if payload2 in uses_map:
#                             use_addr_str = uses_map[payload2]
#                             coverage_mgr.update_coverage_for_defuse(def_addr_str, use_addr_str)
#                             logger.info(f"Def-use coverage updated => {def_addr_str},{use_addr_str}")

#                     # Revert to definitions again
#                     # defs_map = set_breakpoints_for_defs_randomly(
#                     #     gdb, sorted_defs, hw_breakpoints=6
#                     # )
#                     defs_map = set_breakpoints_for_defs_weighted(
#                         gdb, sorted_defs, hw_breakpoints=6
#                     )
#                     gdb.continue_execution()

#                 else:
#                     # Possibly a "use" or unknown BP
#                     logger.info(f"Unknown or use breakpoint => {bkptno}")
#                     # If you want coverage for direct uses:
#                     # if bkptno in uses_map: coverage_mgr.update_coverage_for_defuse(...)
#                     gdb.continue_execution()

#             elif reason == 'timed out':
#                 logger.info("No breakpoints triggered by this test case.")
#                 test_case_count_since_last_trigger += 1
#                 if test_case_count_since_last_trigger > NO_TRIGGER_THRESHOLD:
#                     logger.info("No triggers for too long => re-random definitions.")

#                     ############testing comment this line
#                     # defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
#                     defs_map = set_breakpoints_for_defs_weighted(gdb, sorted_defs, hw_breakpoints=6)
#                     test_case_count_since_last_trigger = 0

#             elif reason in ('exited','crashed'):
#                 logger.warning(f"Target {reason}. Logging input & restarting.")
#                 # Save crashing input
#                 crash_dir = os.path.join(OUTPUT_DIRECTORY, 'crashes')
#                 os.makedirs(crash_dir, exist_ok=True)
#                 crash_file = os.path.join(crash_dir, str(int(time.time())))
#                 with open(crash_file, 'wb') as f:
#                     f.write(test_case_bytes)

#                 # Restart program
#                 restart_program(gdb, elf_path)
#                 # defs_map = set_breakpoints_for_defs_randomly(gdb, sorted_defs, hw_breakpoints=6)
#                 defs_map = set_breakpoints_for_defs_weighted(gdb, sorted_defs, hw_breakpoints=6)
#                 gdb.continue_execution()

#             # Coverage check (dummy example at address=0)
            # timestamp = int(time.time())
            # input_gen.report_address_reached(test_case_bytes, address=0, timestamp=timestamp)

            # if coverage_mgr.check_new_coverage():
            #     log.info("New coverage found => add input to corpus.")
            #     input_gen.add_corpus_entry(test_case_bytes, address=0, timestamp=timestamp)

#             # Generate next input
#             input_gen.choose_new_baseline_input()
#             test_case_bytes = input_gen.generate_input()

#             time.sleep(0.1)

#     except KeyboardInterrupt:
#         logger.info("Stopping fuzzing due to KeyboardInterrupt.")
#     finally:
#         ser.close()
#         coverage_mgr.close()
#         gdb.stop()


# if __name__ == '__main__':
#     main()
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

##########################
# CONSTANTS & TUNING
##########################
HW_BREAKPOINT_LIMIT = 6  # Arduino Due hardware limit
MAX_DEF_TRIES_PER_CHUNK = 1
MAX_USE_TRIES = 1
NUM_ROUNDS = 999999

##########################
# LOGGING SETUP
##########################
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

##########################
# Weighted Random Generator
##########################
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

##########################
# Distances
##########################
def get_closest_uses(def_addr_str, uses_list):
    def_addr = int(def_addr_str, 16)
    return sorted(uses_list, key=lambda u: abs(int(u, 16) - def_addr))

##########################
# GDB CONTROL
##########################
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
    logger.debug("Deleting all existing breakpoints.")
    resp = gdb.send('-break-delete')
    if resp['message'] == 'error':
        err = resp['payload'].get('msg', '')
        if 'No breakpoints to delete' not in err:
            raise Exception(f"Failed to delete breakpoints: {err}")
    else:
        logger.info("Deleted all breakpoints.")

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

##########################
# MAIN
##########################
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

            # (A) Generate exactly ONE test
            test_data = input_gen.generate_input()
            logger.info(f"Round #{round_count} => test_data={test_data!r}")

            # Build weighted-random generator of all defs
            def_generator = get_defs_in_weighted_random_order(all_defs)

            done_with_round = False

            # (B) Chunk the defs in sets of up to 6
            while not done_with_round:
                chunk = []
                for _ in range(HW_BREAKPOINT_LIMIT):
                    try:
                        d_str, u_list = next(def_generator)
                        chunk.append((d_str, u_list))
                    except StopIteration:
                        break

                if not chunk:
                    logger.info("Exhausted all defs in this pass => new test next round.")
                    break  # End of def generator => done this pass.

                # (C) Set breakpoints for these (up to 6) defs
                force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)

                def_bp_map = {}
                for def_addr, uses_list in chunk:
                    bp_id = gdb.set_breakpoint(def_addr)
                    def_bp_map[bp_id] = (def_addr, uses_list)

                gdb.continue_execution()

                # (D) We re-send test_data up to MAX_DEF_TRIES_PER_CHUNK times
                def_triggered = None
                for attempt in range(MAX_DEF_TRIES_PER_CHUNK):
                    logger.info(f"[Chunk Attempt #{attempt+1}] => sending {test_data!r}")
                    resp = send_test_case(ser, test_data)
                    process_response(resp)

                    reason, payload = gdb.wait_for_stop(timeout=3)
                    logger.debug(f"GDB => reason={reason}, payload={payload}")

                    if reason in ("breakpoint hit", "stopped, no reason given"):
                        if payload in def_bp_map:
                            def_addr_str, uses_list = def_bp_map[payload]
                            logger.info(f"Def triggered => {def_addr_str}")
                            coverage_mgr.update_coverage_for_def(def_addr_str)

                            # Remove the def so it doesn't keep firing
                            gdb.remove_breakpoint(payload)
                            del def_bp_map[payload]

                            def_triggered = (def_addr_str, uses_list)
                            break
                        else:
                            logger.debug(f"Unknown breakpoint => {payload}, continuing.")
                            gdb.continue_execution()
                    elif reason == 'timed out':
                        logger.debug("No def triggered this attempt.")
                    elif reason in ('exited','crashed'):
                        logger.warning("Target crashed => restart.")
                        restart_program(gdb, ELF_PATH)
                        break

                # After we've tried sending this chunk
                # >>>> Insert coverage-check snippet here <<<<
                timestamp = int(time.time())
                input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

                if coverage_mgr.check_new_coverage():
                    logger.info("New coverage found => add input to corpus.")
                    input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)

                # done with attempts for this chunk
                force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)
                gdb.continue_execution()

                if def_triggered is not None:
                    # (E) We have a triggered def => set uses chunk by chunk => if any use triggers => done => pick new test
                    def_addr_str, uses_list = def_triggered
                    if uses_list:
                        uses_sorted = get_closest_uses(def_addr_str, uses_list)

                        uses_idx = 0
                        use_triggered = False
                        while uses_idx < len(uses_sorted):
                            uses_chunk = uses_sorted[uses_idx : uses_idx+HW_BREAKPOINT_LIMIT]
                            uses_idx += HW_BREAKPOINT_LIMIT

                            force_halt_if_running(gdb)
                            delete_all_breakpoints(gdb)

                            uses_bp_map = {}
                            for use_addr_str in uses_chunk:
                                ubp_id = gdb.set_breakpoint(use_addr_str)
                                uses_bp_map[ubp_id] = use_addr_str

                            gdb.continue_execution()

                            for attempt_u in range(MAX_USE_TRIES):
                                logger.info(f"[Use Attempt #{attempt_u+1}] => sending {test_data!r}")
                                r2 = send_test_case(ser, test_data)
                                process_response(r2)

                                reason2, payload2 = gdb.wait_for_stop(timeout=3)
                                if reason2 in ("breakpoint hit", "stopped, no reason given"):
                                    if payload2 in uses_bp_map:
                                        use_addr = uses_bp_map[payload2]
                                        logger.info(f"Use triggered => {use_addr}")
                                        coverage_mgr.update_coverage_for_defuse(def_addr_str, use_addr)

                                        gdb.remove_breakpoint(payload2)
                                        del uses_bp_map[payload2]
                                        gdb.continue_execution()
                                        use_triggered = True
                                    else:
                                        gdb.continue_execution()
                                elif reason2 == 'timed out':
                                    logger.debug("No use triggered this attempt.")
                                elif reason2 in ('exited','crashed'):
                                    logger.warning("Target crashed => restart.")
                                    restart_program(gdb, ELF_PATH)
                                    break

                            # After tries for the uses chunk
                            timestamp = int(time.time())
                            input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)
                            if coverage_mgr.check_new_coverage():
                                logger.info("New coverage from uses => add input to corpus.")
                                input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)

                            force_halt_if_running(gdb)
                            delete_all_breakpoints(gdb)
                            gdb.continue_execution()

                        logger.info(f"Done checking uses for def={def_addr_str}, use_triggered={use_triggered}")

                    # After def + uses => pick new test => skip the rest of pass
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

if __name__ == '__main__':
    main()
