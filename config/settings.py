import os

# Logging Configuration
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
# Change to 'INFO' or 'WARNING' to reduce verbosity
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# GDB Configuration
GDB_PATH = 'gdb-multiarch'
GDB_SERVER_ADDRESS = 'localhost:2331'
ELF_PATH = '/home/kai/project/Hardfuzz/example/consule/sketch_nov5a.ino.elf'

# Serial Configuration
SERIAL_PORT = '/dev/ttyACM0'
BAUD_RATE = 38400
SERIAL_TIMEOUT = 1

# Fuzzing Configuration
OUTPUT_DIRECTORY = 'output'
SEEDS_DIRECTORY = 'seeds'
MAX_INPUT_LENGTH = 1024

# Other Configurations
DEF_USE_FILE = 'def_use1.txt'
NO_TRIGGER_THRESHOLD = 2
