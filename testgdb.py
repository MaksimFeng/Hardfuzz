import time
import logging
from fuzzing.gdb_interface import GDB  # your GDB class
from config.settings import ELF_PATH

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# logging.basicConfig(level=logging.DEBUG)

# def test_gdb_communication():
#     gdb = GDB(
#         gdb_path='gdb-multiarch',
#         gdb_server_address='localhost:2331',
#         software_breakpoint_addresses=[],
#         consider_sw_breakpoint_as_error=False
#     )

#     # 1) Connect to your ELF
#     gdb.connect(ELF_PATH)

#     # 2) Hard-reset + halt
#     gdb.send('monitor reset')
#     gdb.send('monitor halt')

#     # 3) Load symbols
#     gdb.send(f'-file-exec-and-symbols {ELF_PATH}')

#     # 4) Insert a breakpoint at main, run
#     gdb.send('-break-insert main')
#     run_resp = gdb.send('-exec-run')
#     if run_resp['message'] == 'error':
#         logging.warning("Could not run => continuing.")
#         gdb.continue_execution()

#     reason, payload = gdb.wait_for_stop(timeout=10)
#     logging.info(f"Initial stop => reason={reason}, payload={payload}")

#     # 5) Now call force_halt_if_running(gdb)
#     logging.info("Testing force_halt_if_running...")
#     gdb = gdb.kill_and_reinit_gdb(ELF_PATH)
#     # gdb.continue_execution()
#     # 6) Check if registers can be read => if so, we know we’re halted
#     # gdb.send('monitor reset')
#     # gdb.send('monitor halt')
#     resp = gdb.send('-data-list-register-values x', timeout=5)
#     logging.info(f"Register read after force_halt_if_running => {resp}")

#     # 7) If everything is good, we can do something else or exit
#     logging.info("Test finished successfully.")

#     gdb.remove_breakpoint('main')
#     gdb.stop()

# if __name__ == '__main__':
#     test_gdb_communication()

def test_queue_reinit():
    """
    This test ensures that we can create a GDB instance, read registers,
    kill & reinit GDB, and read registers again—verifying the
    request_responses queue still works each time.
    """
    logger.info("=== Starting test_queue_reinit ===")

    # 1) Create an initial GDB
    gdb = GDB(
        gdb_path='gdb-multiarch',
        gdb_server_address='localhost:2331',
        software_breakpoint_addresses=[],
        consider_sw_breakpoint_as_error=False
    )

    logger.info("Connecting initial GDB to target...")
    gdb.connect(ELF_PATH)

    # Hard reset/halt, load symbols
    gdb.send('monitor reset')
    gdb.send('monitor halt')
    gdb.send(f'-file-exec-and-symbols {ELF_PATH}')

    # Insert breakpoint at main, run
    gdb.send('-break-insert main')
    run_resp = gdb.send('-exec-run')
    if run_resp['message'] == 'error':
        logger.warning("Initial run => error, trying continue.")
        gdb.continue_execution()

    reason, payload = gdb.wait_for_stop(timeout=5)
    logger.info(f"Initial GDB => reason={reason}, payload={payload}")

    # Try reading registers => ensures queue is OK
    resp1 = gdb.send('-data-list-register-values x', timeout=5)
    logger.info(f"Register read from initial GDB => {resp1}")

    # 2) Kill & reinit
    logger.info("=== Kill & reinit #1 ===")
    gdb = gdb.kill_and_reinit_gdb(ELF_PATH)

    # Now read registers again => ensures queue works after reinit
    resp2 = gdb.send('-data-list-register-values x', timeout=5)
    logger.info(f"Register read from reinit #1 => {resp2}")

    # 3) Optionally do a second kill & reinit
    logger.info("=== Kill & reinit #2 ===")
    gdb = gdb.kill_and_reinit_gdb(ELF_PATH)

    resp3 = gdb.send('-data-list-register-values x', timeout=5)
    logger.info(f"Register read from reinit #2 => {resp3}")

    # 4) Cleanly stop
    gdb.stop()
    logger.info("=== test_queue_reinit finished successfully ===")

if __name__ == '__main__':
    test_queue_reinit()