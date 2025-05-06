PORT=44729
QEMU_USER=qemu-x86_64-static        # or whichever path you use
TARGET=./usr/bin/arm-none-eabi-objdump
ARGS="-D -"
CMD=("$QEMU_USER" -L / -g "$PORT" "$TARGET" $ARGS)

printf 'Running: %q ' "${CMD[@]}"; echo
"${CMD[@]}" </dev/null &
QPID=$!

