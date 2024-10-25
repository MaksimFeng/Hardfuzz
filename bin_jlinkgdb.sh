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

# Corrected variable assignment
GDB_BINARY="gdb-multiarch"

echo "Starting J-Link GDB Server..."
JLinkGDBServer -device $TARGET_DEVICE -if JTAG -speed 4000 -port $GDB_PORT &
GDB_SERVER_PID=$!

sleep 2

# Create a GDB command file
GDB_COMMANDS_FILE=$(mktemp)
# quit
# Write the GDB commands to the file
cat << EOF > "$GDB_COMMANDS_FILE"
set architecture arm
symbol-file
target remote localhost:$GDB_PORT
monitor reset halt
restore $BIN_FILE binary $FLASH_BASE_ADDRESS
monitor reset
monitor go

EOF

echo "Launching GDB to flash the binary..."
$GDB_BINARY -batch -x "$GDB_COMMANDS_FILE"
# $GDB_BINARY -x "$GDB_COMMANDS_FILE"

# Clean up the temporary command file
rm "$GDB_COMMANDS_FILE"

# kill $GDB_SERVER_PID
wait $GDB_SERVER_PID 2>/dev/null

echo "Flashing and execution complete."
