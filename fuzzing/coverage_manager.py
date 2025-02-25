import logging
import numpy as np
# import bitvector
from multiprocessing import shared_memory

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
#4k maybe 
# 64K total coverage size for each map
MAP_SIZE = 65536

class CoverageManager:

    def __init__(self, map_size=MAP_SIZE):
        self.map_size = map_size
        self.total_shm_size = 2 * map_size  # defs + pairs
        # self.trace_bits_defs = BitVector(size=self.map_size)   
        # self.trace_bits_pairs = BitVector(size=self.map_size)  

        # self.virgin_defs = BitVector(size=self.map_size)
        # self.virgin_defs.set_bits_from_string('1' * self.map_size)  # all 1
        # self.virgin_pairs = BitVector(size=self.map_size)
        # self.virgin_pairs.set_bits_from_string('1' * self.map_size) # all 1
        # Allocate a single SHM region of size 2*MAP_SIZE
        logger.debug(f"Allocating shared memory of size: {self.total_shm_size} bytes.")
        self.shm = shared_memory.SharedMemory(create=True, size=self.total_shm_size)

        buffer = self.shm.buf
        self.trace_bits_defs = np.ndarray((map_size,), dtype=np.uint8, buffer=buffer, offset=0)
        self.trace_bits_pairs = np.ndarray((map_size,), dtype=np.uint8, buffer=buffer, offset=map_size)

        self.trace_bits_defs.fill(0)
        self.trace_bits_pairs.fill(0)
        logger.debug("Coverage arrays (trace_bits_defs, trace_bits_pairs) initialized to zero.")

        # 0xFF means "never hit"
        self.virgin_defs = np.full((map_size,), 0xFF, dtype=np.uint8)
        self.virgin_pairs = np.full((map_size,), 0xFF, dtype=np.uint8)
        logger.debug("Virgin arrays (virgin_defs, virgin_pairs) initialized to 0xFF.")

        logger.info("CoverageManager initialized with MAP_SIZE=%d x 2 coverage arrays.", self.map_size)

    def close(self):
        """
        Clean up 
        """
        logger.debug("Closing shared memory.")
        self.shm.close()
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
        logger.debug("Resetting coverage arrays to 0.")
        self.trace_bits_defs.fill(0)
        # self.trace_bits_defs.reset(0)
        self.trace_bits_pairs.fill(0)
        # self.trace_bits_pairs.reset(0)
        logger.info("Coverage arrays reset to zero.")

    def update_coverage_for_def(self, def_addr_str: str):
        """
        For 'definition' coverage, we do:
          idx = (def_addr & 0xFFFF)
        Then set trace_bits_defs[idx] = 1.
        """
        def_addr = int(def_addr_str, 16)
        idx = def_addr & 0xFFFF
        logger.info(f"Updating def coverage for def_addr=0x{def_addr:08X}, idx={idx}")
        self.trace_bits_defs[idx] = 1

    def update_coverage_for_defuse(self, def_addr_str: str, use_addr_str: str):
        """
        For def-use coverage, we do:
          xorVal = def_addr ^ use_addr
          idx = (xorVal & 0xFFFF)
        Then set trace_bits_pairs[idx] = 1.
        """
        def_addr = int(def_addr_str, 16)
        use_addr = int(use_addr_str, 16)
        xorVal = def_addr ^ use_addr
        idx = xorVal & 0xFFFF
        logger.info(f"Updating def-use coverage => def=0x{def_addr:08X}, use=0x{use_addr:08X}, idx={idx}")
        self.trace_bits_pairs[idx] = 1

    def check_new_coverage(self) -> bool:
        # for i in range(self.map_size):
        #     if self.trace_bits_defs[i] == 1 and self.virgin_defs[i] == 1:
        #         self.virgin_defs[i] = 0
        #         new_bits_found = True
        #         logger.debug(f"New def coverage => index={i}")
        new_bits_found = False
        logger.debug("Checking for new coverage in def coverage...")

        # Check def coverage
        hits_defs = np.where(self.trace_bits_defs != 0)[0]
        for i in hits_defs:
            if self.virgin_defs[i] == 0xFF:
                self.virgin_defs[i] = 0x00
                logger.info(f"New def coverage found => index {i}")
                new_bits_found = True

        # Check def-use coverage
        logger.debug("Checking for new coverage in def-use coverage...")
        hits_pairs = np.where(self.trace_bits_pairs != 0)[0]
        for i in hits_pairs:
            if self.virgin_pairs[i] == 0xFF:
                self.virgin_pairs[i] = 0x00
                logger.debug(f"New def-use coverage found => index {i}")
                new_bits_found = True

        if new_bits_found:
            logger.info("New coverage detected.")
        else:
            logger.info("No new coverage found.")

        return new_bits_found
    