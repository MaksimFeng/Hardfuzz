#!/bin/bash

if [ $# -lt 1 ]; then
  echo "Usage: $0 <path_to_bin_file>"
  exit 1
fi

BIN_FILE="$1"

TARGET_DEVICE="ATSAM3X8E"
FLASH_BASE_ADDRESS="0x00080000"

GDB_PORT="2331"
GDB_SERVER_BINARY="JLinkGDBServer"
GDB_BINARY="gdb-multiarch"

cleanup() {
  echo "Terminating GDB Server..."
  kill $GDB_SERVER_PID 2>/dev/null
  wait $GDB_SERVER_PID 2>/dev/null
}

trap cleanup EXIT

echo "Starting J-Link GDB Server..."
$GDB_SERVER_BINARY -device $TARGET_DEVICE -if JTAG -speed 4000 -port $GDB_PORT &
GDB_SERVER_PID=$!

Wait for GDB server to be ready
for i in {1..2}; do
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

echo "BIN_FILE: $BIN_FILE"

if [ ! -f "$BIN_FILE" ]; then
  echo "Error: File '$BIN_FILE' not found."
  exit 1
fi

INPUT_DATA=$(cat -)

INPUT_VALUE=$(echo -n "$INPUT_DATA" | od -An -t u4 -N 4 | tr -d ' ')

if [ -z "$INPUT_VALUE" ]; then
  INPUT_VALUE=0
fi

GDB_COMMANDS_FILE=$(mktemp)

cat << EOF > "$GDB_COMMANDS_FILE"
set pagination off
set logging off
set target-async off
set architecture arm
set arm force-mode thumb
target remote localhost:$GDB_PORT
monitor reset halt
restore $BIN_FILE binary $FLASH_BASE_ADDRESS
monitor reset halt

# Set \$r1 to the input value
set \$r1 = $INPUT_VALUE
echo "Injected input into R1: $INPUT_VALUE\n"

# Continue execution
continue

# Exit GDB
quit
EOF

echo "Launching GDB..."
$GDB_BINARY --batch -x "$GDB_COMMANDS_FILE"

GDB_EXIT_STATUS=$?

rm "$GDB_COMMANDS_FILE"

echo "GDB session has ended."


exit $GDB_EXIT_STATUS
