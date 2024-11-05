from pygdbmi.gdbcontroller import GdbController

def connect_gdb():
    # Create a GDB controller instance
    gdbmi = GdbController(
        command=['gdb-multiarch', '--interpreter=mi2'],  # Path to your ARM GDB executable
        # verbose=False
    )

    # Connect to the JLink GDB Server
    gdbmi.write('-file-exec-and-symbols /home/kai/project/Hardfuzz/example/rots_consile.ino.elf')

    # Connect to the JLink GDB Server
    gdbmi.write('-target-select remote localhost:2331')

    print("Connected to GDB Server.")
    return gdbmi

def set_breakpoint(gdbmi, location):
    # Set a breakpoint at the specified location
    response = gdbmi.write(f'-break-insert {location}')
    print(f"Breakpoint set at {location}")
    return response

def set_watchpoint(gdbmi, expression):
    # Set a watchpoint on the specified expression
    response = gdbmi.write(f'-break-watch {expression}')
    print(f"Watchpoint set on {expression}")
    return response

def continue_execution(gdbmi):
    # Continue execution
    response = gdbmi.write('-exec-continue')
    print("Continuing execution.")
    return response

def main():
    gdbmi = connect_gdb()

    try:
        # Example: Set a breakpoint at 'main'
        set_breakpoint(gdbmi, 'main')

        # Example: Set a watchpoint on a variable 'myVariable'
        # set_watchpoint(gdbmi, 'myVariable')

        # Continue execution
        continue_execution(gdbmi)

        # Monitor for GDB events
        while True:
            responses = gdbmi.get_gdb_response(timeout_sec=1)
            for response in responses:
                if response['message'] == 'stopped':
                    reason = response['payload'].get('reason', '')
                    if reason == 'breakpoint-hit':
                        addr = response['payload'].get('frame', {}).get('addr', '')
                        func = response['payload'].get('frame', {}).get('func', '')
                        print(f"Breakpoint hit at {func} ({addr})")
                        # Take action or continue execution
                        continue_execution(gdbmi)
                    elif reason == 'watchpoint-trigger':
                        print("Watchpoint triggered.")
                        # Handle watchpoint trigger
                        continue_execution(gdbmi)
    except KeyboardInterrupt:
        print("Stopping GDB session.")
    finally:
        gdbmi.exit()

if __name__ == '__main__':
    main()
