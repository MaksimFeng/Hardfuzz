from pygdbmi.gdbcontroller import GdbController

def connect_gdb():
    gdbmi = GdbController(
        command=['gdb-multiarch', '--interpreter=mi2'],  
        # verbose=False
    )

    gdbmi.write('-file-exec-and-symbols /home/kai/project/Hardfuzz/example/rots_consile.ino.elf')

    gdbmi.write('-target-select remote localhost:2331')

    print("Connected to GDB Server.")
    return gdbmi

def set_breakpoint(gdbmi, location):
    response = gdbmi.write(f'-break-insert {location}')
    print(f"Breakpoint set at {location}")
    return response

def set_watchpoint(gdbmi, expression):
    response = gdbmi.write(f'-break-watch {expression}')
    print(f"Watchpoint set on {expression}")
    return response

def continue_execution(gdbmi):
    response = gdbmi.write('-exec-continue')
    print("Continuing execution.")
    return response

def main():
    gdbmi = connect_gdb()

    try:
        set_breakpoint(gdbmi, 'main')

        continue_execution(gdbmi)

        while True:
            responses = gdbmi.get_gdb_response(timeout_sec=1)
            for response in responses:
                if response['message'] == 'stopped':
                    reason = response['payload'].get('reason', '')
                    if reason == 'breakpoint-hit':
                        addr = response['payload'].get('frame', {}).get('addr', '')
                        func = response['payload'].get('frame', {}).get('func', '')
                        print(f"Breakpoint hit at {func} ({addr})")
                        continue_execution(gdbmi)
                    elif reason == 'watchpoint-trigger':
                        print("Watchpoint triggered.")
                        continue_execution(gdbmi)
    except KeyboardInterrupt:
        print("Stopping GDB session.")
    finally:
        gdbmi.exit()

if __name__ == '__main__':
    main()
