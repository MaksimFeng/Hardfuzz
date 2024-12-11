#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <path_to_bin_file>"
  exit 1
fi

BIN_FILE="$1"

if [ ! -f "$BIN_FILE" ]; then
  echo "Error: File '$BIN_FILE' not found."
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

# Create a GDB command file
GDB_COMMANDS_FILE=$(mktemp)
#break *0x0008415b
# continue  restore $BIN_FILE binary $FLASH_BASE_ADDRESS

# Write the GDB commands to the file
cat << EOF > "$GDB_COMMANDS_FILE"
set architecture arm
target remote localhost:$GDB_PORT
set arm force-mode thumb
monitor reset halt
monitor reset halt

EOF

echo "Launching GDB for interactive debugging..."
$GDB_BINARY -x "$GDB_COMMANDS_FILE"

# Clean up the temporary command file
rm "$GDB_COMMANDS_FILE"

echo "GDB session has ended."

# The 'cleanup' function will be called automatically due to 'trap'
