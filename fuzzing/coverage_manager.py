import logging
import numpy as np
from multiprocessing import shared_memory

logger = logging.getLogger(__name__)

MAP_SIZE = 65536

class CoverageManager:
    """
    Manages two coverage bitmaps as saturating counters:
      1) trace_bits_defs   (uint8) coverage for definitions
      2) trace_bits_pairs  (uint8) coverage for def–use pairs

    Each entry can be [0..255], incremented each time we see a hit
    (capped at 255). "Virgin" arrays track if an index was never hit
    before (0xFF) or has been discovered (0x00).

    Also, we keep pairs_debug_map to store the actual def_addr/use_addr
    pairs that mapped to each coverage index for debugging.
    """

    def __init__(self, map_size=MAP_SIZE):
        self.map_size = map_size
        self.total_shm_size = 2 * map_size

        logger.debug(f"Allocating shared memory => size={self.total_shm_size} bytes.")
        self.shm = shared_memory.SharedMemory(create=True, size=self.total_shm_size)

        buffer = self.shm.buf
        self.trace_bits_defs = np.ndarray(
            (map_size,), dtype=np.uint8, buffer=buffer, offset=0
        )
        self.trace_bits_pairs = np.ndarray(
            (map_size,), dtype=np.uint8, buffer=buffer, offset=map_size
        )

        # initialize counters to 0
        self.trace_bits_defs.fill(0)
        self.trace_bits_pairs.fill(0)

        # virgin arrays => 0xFF means "never hit"
        self.virgin_defs = np.full((map_size,), 0xFF, dtype=np.uint8)
        self.virgin_pairs = np.full((map_size,), 0xFF, dtype=np.uint8)

        # For debugging/investigation => index => set of (def, use) pairs
        self.pairs_debug_map = {}
        # You might also store def_debug_set = {} if you want def-based logs.

        logger.info("CoverageManager (saturating counters) init done.")

    def close(self):
        logger.debug("Closing SHM in CoverageManager.")
        self.shm.close()
        try:
            self.shm.unlink()
        except FileNotFoundError:
            pass
        logger.info("SharedMemory unlinked. CoverageManager closed.")

    def reset_coverage(self):
        """
        Reset the saturating counters to 0 for a new test,
        but keep the 'virgin' arrays so we know what's new vs. old.
        """
        logger.debug("Reset coverage arrays to 0.")
        self.trace_bits_defs.fill(0)
        self.trace_bits_pairs.fill(0)

    def update_coverage_for_def(self, def_addr_str: str):
        """
        def coverage => index = def_addr & 0xFFFF
        saturating increment => min(current+1, 255)
        """
        def_addr = int(def_addr_str, 16)
        idx = def_addr & 0xFFFF
        old_val = self.trace_bits_defs[idx]
        if old_val < 255:
            self.trace_bits_defs[idx] = old_val + 1

        # if you want to store debugging info for defs, you can do so here
        # e.g. def_debug_map[idx].add(def_addr) or something similar

    def update_coverage_for_defuse(self, def_addr_str: str, use_addr_str: str):
        """
        def–use coverage => index = (def_addr ^ use_addr) & 0xFFFF
        saturating increment => min(current+1, 255)
        also store the pair in pairs_debug_map for later reference
        """
        def_addr = int(def_addr_str, 16)
        use_addr = int(use_addr_str, 16)
        xorVal = def_addr ^ use_addr
        idx = xorVal & 0xFFFF

        # saturating increment
        old_val = self.trace_bits_pairs[idx]
        if old_val < 255:
            self.trace_bits_pairs[idx] = old_val + 1

        # debug map => store the actual addresses future use
        if idx not in self.pairs_debug_map:
            self.pairs_debug_map[idx] = set()
        self.pairs_debug_map[idx].add((def_addr, use_addr))

    def check_new_coverage(self) -> bool:
        """
        For saturating counters:
          If trace_bits_[i] > 0 and virgin_[i] == 0xFF => new coverage
          set virgin_[i] = 0x00
        Return True if any new coverage was found.
        """
        new_bits_found = False

        # check defs coverage
        hit_indices = np.where(self.trace_bits_defs > 0)[0]
        for i in hit_indices:
            if self.virgin_defs[i] == 0xFF:
                self.virgin_defs[i] = 0x00
                logger.debug(f"New def coverage => index={i}, value={self.trace_bits_defs[i]}")
                new_bits_found = True

        # check pairs coverage
        hit_indices = np.where(self.trace_bits_pairs > 0)[0]
        for i in hit_indices:
            if self.virgin_pairs[i] == 0xFF:
                self.virgin_pairs[i] = 0x00
                logger.debug(f"New def-use coverage => index={i}, value={self.trace_bits_pairs[i]}")
                new_bits_found = True

        if new_bits_found:
            logger.info("New coverage discovered!")
        else:
            logger.info("No new coverage found this test.")

        return new_bits_found
