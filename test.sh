#!/bin/bash

if [ $# -lt 2 ]; then
  echo "Usage: $0 <path_to_bin_file> <input_file>"
  exit 1
fi

BIN_FILE="$1"
INPUT_FILE="$2"

if [ ! -f "$BIN_FILE" ]; then
  echo "Error: File '$BIN_FILE' not found."
  exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: Input file '$INPUT_FILE' not found."
  exit 1
fi

# Target device and flash memory base address for the Arduino Due
TARGET_DEVICE="ATSAM3X8E"
FLASH_BASE_ADDRESS="0x00080000"

GDB_PORT="2331"
GDB_SERVER_BINARY="JLinkGDBServer"
GDB_BINARY="gdb-multiarch"

# Function to clean up background processes
cleanup() {
  echo "Terminating GDB Server..."
  kill $GDB_SERVER_PID 2>/dev/null
  wait $GDB_SERVER_PID 2>/dev/null
}

# Set trap to call cleanup on EXIT
trap cleanup EXIT

echo "Starting J-Link GDB Server..."
$GDB_SERVER_BINARY -device $TARGET_DEVICE -if JTAG -speed 4000 -log gdbserver.log -port $GDB_PORT &
GDB_SERVER_PID=$!

# Wait for GDB server to be ready
for i in {1..10}; do
  if lsof -i :$GDB_PORT >/dev/null; then
    echo "GDB Server is ready."
    break
  fi
  echo "Waiting for GDB Server to start..."
  sleep 1
done

if ! lsof -i :$GDB_PORT >/dev/null; then
  echo "Error: GDB Server failed to start."
  exit 1
fi

# Read the input data from the input file
INPUT_DATA=$(cat "$INPUT_FILE")

# Convert the input data into a numerical value suitable for R1
# For example, read the first 4 bytes and convert to integer
INPUT_VALUE=$(od -An -t u4 -N 4 "$INPUT_FILE" | tr -d ' ')

# If the input file is less than 4 bytes, pad with zeros
if [ -z "$INPUT_VALUE" ]; then
  INPUT_VALUE=0
fi

# Create a GDB command file
GDB_COMMANDS_FILE=$(mktemp)

# Write the GDB commands to the file
cat << EOF > "$GDB_COMMANDS_FILE"
set architecture arm
target remote localhost:$GDB_PORT
set arm force-mode thumb
monitor reset halt
restore $BIN_FILE binary $FLASH_BASE_ADDRESS
monitor reset halt


set \$r1 = $INPUT_VALUE
echo "Injected input into R1: $INPUT_VALUE\n"
# Continue execution
continue

# Exit GDB
# quit 0
EOF

echo "Launching GDB..."
$GDB_BINARY --batch -x "$GDB_COMMANDS_FILE"

GDB_EXIT_STATUS=$?

# Clean up the temporary command file
rm "$GDB_COMMANDS_FILE"

echo "GDB session has ended."

# The 'cleanup' function will be called automatically due to 'trap'

exit $GDB_EXIT_STATUS
