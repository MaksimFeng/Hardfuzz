    #!/usr/bin/env bash
0
    # Environment overrides (optional):
    #   QEMU_USER   – path to qemu-*-static          (default: qemu-x86_64-static)
    #   TARGET_BIN  – path to target binary          (default: ./usr/bin/arm-none-eabi-objdump)
    #   TARGET_ARGS – quoted string with target args (default: "-D -")
    #   SYSROOT     – directory used as / inside QEMU (default: /)
    #
    set -euo pipefail

    QEMU_USER="${QEMU_USER:-qemu-x86_64-static}"
    TARGET_BIN="${TARGET_BIN:-/usr/bin/arm-none-eabi-objdump}"
    TARGET_ARGS="${TARGET_ARGS:-"-D -"}"
    SYSROOT="${SYSROOT:-/}"

    # pick a free TCP port
    PORT=$(python3 - <<'PY'
import socket, contextlib
with contextlib.closing(socket.socket()) as s:
    s.bind(('', 0))
    print(s.getsockname()[1])
PY
    )

    echo "Launching QEMU:"
    echo "  $QEMU_USER -L $SYSROOT -g $PORT $TARGET_BIN $TARGET_ARGS"
    echo

    "$QEMU_USER" -L "$SYSROOT" -g "$PORT" "$TARGET_BIN" $TARGET_ARGS < /dev/null &
    QPID=$!

    echo "QEMU PID    : $QPID"
    echo "GDB endpoint: localhost:$PORT"
    echo "Attach with : gdb -q -ex 'target remote :$PORT'"
    echo

    # wait for qemu to exit and print its status
    wait $QPID
    EXIT=$?
    echo "QEMU exited with status $EXIT"
    exit $EXIT
