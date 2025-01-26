import logging
import numpy as np
from multiprocessing import shared_memory

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

#64K for each coverage map. 2 maps => total 2 * 65536 in SHM.
MAP_SIZE = 65536

class CoverageManager:
    """
    Manages TWO coverage bitmaps in a single shared memory block:
    1) Def coverage     (trace_bits_defs)
    2) Def–Use coverage (trace_bits_pairs)

    Also tracks separate 'virgin' arrays for each to detect new coverage.
    """

    def __init__(self, map_size=MAP_SIZE):
        self.map_size = map_size
        self.total_shm_size = 2 * map_size  # defs + pairs

        # Allocate a single SHM region of size 2*MAP_SIZE
        logger.debug(f"Allocating shared memory of size: {self.total_shm_size} bytes.")
        self.shm = shared_memory.SharedMemory(create=True, size=self.total_shm_size)

        # Create two numpy slices: [0..map_size-1] for defs, [map_size..2*map_size-1] for pairs.
        buffer = self.shm.buf
        self.trace_bits_defs = np.ndarray((map_size,), dtype=np.uint8, buffer=buffer, offset=0)
        self.trace_bits_pairs = np.ndarray((map_size,), dtype=np.uint8, buffer=buffer, offset=map_size)

        # Initialize coverage arrays to zero
        self.trace_bits_defs.fill(0)
        self.trace_bits_pairs.fill(0)
        logger.debug("Coverage arrays (trace_bits_defs, trace_bits_pairs) initialized to zero.")

        # "Virgin" arrays for each map. 0xFF means "never hit"
        self.virgin_defs = np.full((map_size,), 0xFF, dtype=np.uint8)
        self.virgin_pairs = np.full((map_size,), 0xFF, dtype=np.uint8)
        logger.debug("Virgin arrays (virgin_defs, virgin_pairs) initialized to 0xFF.")

        logger.info("CoverageManager initialized with MAP_SIZE=%d x 2 coverage arrays.", self.map_size)

    def close(self):
        """
        Clean up the shared memory segment.
        """
        logger.debug("Closing shared memory.")
        self.shm.close()
        # In a single-process scenario, also remove the SHM from the system.
        try:
            self.shm.unlink()
            logger.debug("Shared memory unlinked successfully.")
        except FileNotFoundError:
            logger.warning("Shared memory unlink failed: FileNotFoundError.")
        logger.info("CoverageManager SHM removed.")

    def reset_coverage(self):
        """
        Clear coverage arrays (defs + pairs) between test cases.
        """
        logger.debug("Resetting coverage arrays.")
        self.trace_bits_defs.fill(0)
        self.trace_bits_pairs.fill(0)
        logger.info("Coverage arrays reset to zero.")

    def update_coverage_for_def(self, def_addr_str: str):
        """
        Mark coverage for a single 'definition' address.
        Convert hex string to int, compute index, set or XOR coverage.
        """
        address = int(def_addr_str, 16)
        idx = address % self.map_size
        logger.debug(f"Updating def coverage for address {def_addr_str} at index {idx}.")
        self.trace_bits_defs[idx] ^= 0xAA
        logger.info(f"Def coverage updated at index {idx} with XOR 0xAA.")

    def update_coverage_for_defuse(self, def_addr_str: str, use_addr_str: str):
        """
        Mark coverage for a (def, use) pair. 
        Combine def_addr + use_addr in a simple hash => index, then update pairs map.
        """
        def_addr = int(def_addr_str, 16)
        use_addr = int(use_addr_str, 16)
        combo_hash = (def_addr * 31) ^ use_addr
        idx = combo_hash % self.map_size
        logger.debug(f"Updating def-use coverage for addresses {def_addr_str}, {use_addr_str} at index {idx}.")
        self.trace_bits_pairs[idx] ^= 0xFF
        logger.info(f"Def-use coverage updated at index {idx} with XOR 0xFF.")

    def check_new_coverage(self) -> bool:
        """
        Compare current coverage in trace_bits_* to the corresponding virgin_* array
        to see if any new bits are covered for either defs or pairs.
        Return True if new coverage is found; else False.
        """
        new_bits_found = False
        logger.debug("Checking for new coverage...")

        # Check defs coverage
        for i in range(self.map_size):
            if self.trace_bits_defs[i] != 0 and self.virgin_defs[i] == 0xFF:
                self.virgin_defs[i] = 0x00  # no longer virgin
                logger.debug(f"New def coverage found at index {i}.")
                new_bits_found = True

        # Check def–use coverage
        for i in range(self.map_size):
            if self.trace_bits_pairs[i] != 0 and self.virgin_pairs[i] == 0xFF:
                self.virgin_pairs[i] = 0x00
                logger.debug(f"New def-use coverage found at index {i}.")
                new_bits_found = True

        if new_bits_found:
            logger.info("New coverage detected.")
        else:
            logger.info("No new coverage found.")

        return new_bits_found
