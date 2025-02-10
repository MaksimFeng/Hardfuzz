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

                force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)

                def_bp_map = {}
                for def_addr, uses_list in chunk:
                    bp_id = gdb.set_breakpoint(def_addr)
                    def_bp_map[bp_id] = (def_addr, uses_list)

                gdb.continue_execution()

                def_triggered = None
                for attempt in range(MAX_DEF_TRIES_PER_CHUNK):
                    logger.info(f"[def Attempt #{attempt+1}] => sending {test_data!r}")
                    resp = send_test_case(ser, test_data)
                    process_response(resp)

                    reason, payload = gdb.wait_for_stop(timeout=3)
                    logger.debug(f"GDB => reason={reason}, payload={payload}")

                    if reason in ("breakpoint hit", "stopped, no reason given"):
                        if payload in def_bp_map:
                            def_addr_str, uses_list = def_bp_map[payload]
                            logger.info(f"Def triggered => {def_addr_str}")
                            coverage_mgr.update_coverage_for_def(def_addr_str)

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

                # [NEW LOGIC FOR COVERAGE]
                timestamp = int(time.time())
                # 'report_address_reached' => might add new corpus entry if not in corpus
                input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)

                if coverage_mgr.check_new_coverage():
                    logger.info("New coverage found => add input to corpus.")
                    input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
                    

                    # logger.info("Choosing new baseline because coverage changed.")
                    # input_gen.choose_new_baseline_input()

                force_halt_if_running(gdb)
                delete_all_breakpoints(gdb)
                gdb.continue_execution()

                if def_triggered is not None:
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

                            # [COVERAGE AFTER USES]
                            timestamp = int(time.time())
                            input_gen.report_address_reached(test_data, address=0, timestamp=timestamp)
                            # if coverage_mgr.check_new_coverage():
                            #     logger.info("New coverage from uses => add input to corpus.")
                            #     input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
                                

                            #     logger.info("Choosing new baseline because coverage changed in uses.")
                            #     input_gen.choose_new_baseline_input()

                            force_halt_if_running(gdb)
                            delete_all_breakpoints(gdb)
                            gdb.continue_execution()

                        if coverage_mgr.check_new_coverage():
                            logger.info("New coverage from uses => add input to corpus.")
                            input_gen.add_corpus_entry(test_data, address=0, timestamp=timestamp)
                            input_gen.retry_corpus_input_index = len(input_gen.corpus)
                            logger.info("Choosing new baseline because coverage changed in uses.")
                            #force to change the testcase rightaway
                            # input_gen.current_base_input_index = len(input_gen.corpus) - 1

                            input_gen.choose_new_baseline_input()
                        logger.info(f"Done checking uses for def={def_addr_str}, use_triggered={use_triggered}")

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
