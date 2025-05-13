from __future__ import annotations

import logging
import logging.handlers
import random
import time
from pathlib import Path

from fuzzing.coverage_manager import CoverageManager
from fuzzing.input_generation import InputGeneration
from fuzzing.qemu_instance import QEMUInstance
from utils.file_parsing import parse_block_with_full_details
from config.settings import (
    LOG_DATEFMT,
    LOG_FILE,
    LOG_FORMAT,
    LOG_LEVEL,
    OUTPUT_DIRECTORY,
    SEEDS_DIRECTORY,
    DEF_USE_FILE,
)

QEMU_USER   = "qemu-x86_64"
TARGET_BIN  = "/usr/bin/x86_64-linux-gnu-objdump"
# TARGET_BIN = "/project/new_test"
# TARGET_ARGS = ["-D", "-"]          # passed to the target; 
TARGET_ARGS = ["-D", "-"]          # passed to the target;
GDB_PATH    = "gdb-multiarch"
SYSROOT     = "/"
FIXED_PORT  = 2331
HW_BP_LIMIT = 6

logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
_fmt = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT)

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
logger.addHandler(_ch)

_fh = logging.handlers.RotatingFileHandler(
    Path(OUTPUT_DIRECTORY, "fuzzer.log"),
    maxBytes=20 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
_fh.setFormatter(_fmt)
logger.addHandler(_fh)

import pygdbmi.gdbcontroller  # noqa: E402
pygdbmi.gdbcontroller.logger.setLevel(logging.DEBUG)


def _flatten_def_use() -> list[tuple[str, list[str]]]:
    parsed = parse_block_with_full_details(DEF_USE_FILE)
    flat: list[tuple[str, list[str]]] = []
    for block, defs in parsed.items():
        uses = {
            u for d in defs for u in d["use_block_addrs"]
            if not u.lower().startswith("(")
        }
        flat.append((block, sorted(uses)))
    logger.info("Parsed %d definition blocks", len(flat))
    return flat


def _weighted_generator(def_list, global_hits: dict[str, int]):
    bag = [(d, u, max(1, len(u))) for d, u in def_list]
    local_hits = {d: 0 for d, *_ in bag}
    while True:
        total = 0.0
        tmp: list[tuple[str, list[str], float]] = []
        for d, u, base in bag:
            w = base / (1 + local_hits[d]) / (1 + global_hits.get(d, 0)) ** 0.5
            tmp.append((d, u, w)); total += w
        r = random.random() * total
        acc = 0.0
        for d, u, w in tmp:
            acc += w
            if acc >= r:
                local_hits[d] += 1
                yield d, u
                break


def _run_one_case(
    qemu: QEMUInstance,
    stdin_data: bytes,
    def_use_list: list[tuple[str, list[str]]],
    cov: CoverageManager,
    global_hits: dict[str, int],
) -> bool:
    """Execute a single fuzz iteration inside *qemu*."""

    # feed the testcase
    # logger.debug("Feeding %d bytes to QEMU", str(stdin_data))
    

    gdb = qemu.gdb
    def_gen = _weighted_generator(def_use_list, global_hits)

    alive = True
    qemu.process.stdin.write(stdin_data)
    qemu.process.stdin.flush()
    while alive:
        chunk = [next(def_gen) for _ in range(HW_BP_LIMIT)]
        if not chunk:
            break

        gdb.send("-break-delete")
        bp_map = {gdb.set_breakpoint(d): d for d, _ in chunk}

        gdb.continue_execution()
        # qemu.process.stdin.write(stdin_data)
        # qemu.process.stdin.flush()
        while bp_map and alive:
            reason, payload = gdb.wait_for_stop(timeout=5)

            if reason == "breakpoint hit" and payload in bp_map:
                d_hex = bp_map.pop(payload)
                global_hits[d_hex] = global_hits.get(d_hex, 0) + 1
                cov.update_coverage_for_def(d_hex)
                gdb.remove_breakpoint(payload)
                if bp_map:
                    gdb.continue_execution()
                    continue
                break

            if reason.startswith(("exited", "communication error")):
                qemu.process.stdin.close()
                logger.debug("QEMU exited or communication error")
                alive = False
                break

            logger.debug("Unhandled stop reason %s", reason)
            alive = False
            break

    got_new = cov.check_new_coverage()
    cov.reset_coverage()
    qemu.stop()
    return got_new



def main() -> None:
    Path(OUTPUT_DIRECTORY).mkdir(parents=True, exist_ok=True)

    coverage = CoverageManager()
    corpus = InputGeneration(
        output_directory=OUTPUT_DIRECTORY,
        seeds_directory=SEEDS_DIRECTORY,
        max_input_length=4096,
    )

    def_use = _flatten_def_use()
    global_hits: dict[str, int] = {}
    

    for rnd in range(1, 1_000_000):
        corpus.choose_new_baseline_input()
        inp = corpus.generate_input()
        logger.info("Round %d – len=%d", rnd, len(inp))

        qemu = QEMUInstance(
            elf_path   = TARGET_BIN,
            qemu_path  = QEMU_USER,
            gdb_path   = GDB_PATH,
            gdb_port   = FIXED_PORT,
            qemu_args  = ["-L", SYSROOT],   
            target_args= TARGET_ARGS,       
            stderr_dir = OUTPUT_DIRECTORY,
            pause_at_entry=True,
        )

        got_new = _run_one_case(qemu, inp, def_use, coverage, global_hits)
        if got_new:
            corpus.add_corpus_entry(inp, address=0, timestamp=int(time.time()))
            logger.info("New coverage → corpus size %d", len(corpus.corpus))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted – exiting.")