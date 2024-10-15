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

# target device and flash memory base address for the Arduino Due
TARGET_DEVICE="ATSAM3X8E"
FLASH_BASE_ADDRESS="0x00080000"

JLINK_COMMANDS_FILE=$(mktemp)

cat << EOF > "$JLINK_COMMANDS_FILE"
device $TARGET_DEVICE
r
h
loadbin $BIN_FILE, $FLASH_BASE_ADDRESS
r
g
exit
EOF

# Run the JLinkExe with the generated command file
JLinkExe -CommanderScript "$JLINK_COMMANDS_FILE"

# Clean up the temporary command file
rm "$JLINK_COMMANDS_FILE"

echo "Flashing and execution complete."
