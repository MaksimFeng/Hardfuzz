import os

# Logging Configuration
# LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
# Change to 'INFO' or 'WARNING' 
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'
LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'log.txt')
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# GDB Configuration
GDB_PATH = 'gdb-multiarch'
GDB_SERVER_ADDRESS = 'localhost:2331'
ELF_PATH = '/home/kai/project/Hardfuzz/example/sketch_nov5a.ino.elf'

# Serial Configuration
SERIAL_PORT = '/dev/ttyACM0'
BAUD_RATE = 38400
SERIAL_TIMEOUT = 1

# Fuzzing Configuration
OUTPUT_DIRECTORY = 'output'
SEEDS_DIRECTORY = 'seeds'
MAX_INPUT_LENGTH = 10240

DEF_USE_FILE = 'def_use1.txt'
NO_TRIGGER_THRESHOLD = 2
