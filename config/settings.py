import os

# Logging Configuration
# LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
# Change to 'INFO' or 'WARNING' 
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'
# LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'log_buggy2.txt')
# LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'log_buggy3.txt')

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs_05/07', 'log5.txt')

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# GDB Configuration
GDB_PATH = 'gdb-multiarch'
GDB_SERVER_ADDRESS = 'localhost:2331'
# ELF_PATH = '/home/kai/Arduino/program1_json/build/arduino.sam.arduino_due_x_dbg/program1_json.ino.elf'
# ELF_PATH = '/home/kai/project/Hardfuzz/example/sketch_nov5a.ino.elf'
# ELF_PATH = '/home/kai/Arduino/program2_buggy/build/arduino.sam.arduino_due_x_dbg/program2_buggy.ino.elf'
# ELF_PATH = '/home/kai/Arduino/program3/build/arduino.sam.arduino_due_x_dbg/program3.ino.elf'
ELF_PATH = '/home/kai/Arduino/programbuggynochange/build/arduino.sam.arduino_due_x_dbg/programbuggynochange.ino.elf'
# Serial Configuration
SERIAL_PORT = '/dev/ttyACM1'
BAUD_RATE = 38400
SERIAL_TIMEOUT = 1

# Fuzzing Configuration
OUTPUT_DIRECTORY = 'output'

# OUTPUT_DIRECTORY = 'output_buggy'
SEEDS_DIRECTORY = 'seeds'
# SEEDS_DIRECTORY = 'seed_buggy'
MAX_INPUT_LENGTH = 10240

# DEF_USE_FILE = 'def_use1.txt'
# DEF_USE_FILE = 'new_all.txt'
# DEF_USE_FILE = 'block.txt'
# DEF_USE_FILE = 'block_def_use.txt'
DEF_USE_FILE = 'block_def_use_buggycode.txt'
# DEF_USE_FILE = 'blocks.txt' # blocks before change
# DEF_USE_FILE = 'external1.txt'
# DEF_USE_FILE = '/home/kai/Arduino/program2_buggy/build/arduino.sam.arduino_due_x_dbg/def_use1.txt'
# DEF_USE_FILE = '/home/kai/Arduino/program2_buggy/build/arduino.sam.arduino_due_x_dbg/def_use1.txt'
# DEF_USE_FILE = '/home/kai/Arduino/program3/build/arduino.sam.arduino_due_x_dbg/def_use.txt'
# DEF_USE_FILE = '/home/kai/Arduino/programbuggynochange/build/arduino.sam.arduino_due_x_dbg/def_use1.txt'
NO_TRIGGER_THRESHOLD = 2
