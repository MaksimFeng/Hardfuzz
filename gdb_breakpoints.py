from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
import time
def connect_gdb():
    gdbmi = GdbController(
        command=['gdb-multiarch', '--interpreter=mi2'],  
        # verbose=False
    )
    gdbmi.write('-file-exec-and-symbols /home/kai/project/Hardfuzz/example/consule/sketch_nov5a.ino.bin')
    gdbmi.write('-target-select remote localhost:2331')
    print("Connected to GDB Server.")
    return gdbmi

def set_breakpoint(gdbmi, address):
    # address should be something like "0x848e4"
    response = gdbmi.write(f'-break-insert *{address}')
    bkptno = extract_bkpt_number(response)
    print(f"Breakpoint set at {address}, bkptno={bkptno}")
    return bkptno

def set_watchpoint(gdbmi, address):
    # Try casting the address to a char pointer to form a valid C expression:

    expression = f'*(char*){address}'
    # If -break-watch doesn't work, try using -break-insert -w -h:
    # print(f"Setting watchpoint at {expression}")
    response = gdbmi.write(f'-break-watch {expression}', timeout_sec=1)
    print(response)
    bkptno = extract_bkpt_number(response)
    print(f"Watchpoint set at {expression}, bkptno={bkptno}")
    return bkptno

def continue_execution(gdbmi):
    response = gdbmi.write('-exec-continue')
    # gdbmi.write('continue')
    print("Continuing execution.")
    return response

def extract_bkpt_number(response):
    # response is a list of dicts
    # Look for 'bkpt' or 'wpt' in payload
    for r in response:
        if r['type'] == 'result':
            if 'bkpt' in r['payload']:
                return r['payload']['bkpt']['number']
            elif 'wpt' in r['payload']:
                return r['payload']['wpt']['number']
    return None

#process data:
def parse_address(line):
    #Extract the hex address and return it as a string (keep hex format)
    parts = line.strip().split()
    hex_addr_str = parts[-1]
    return hex_addr_str

def sort_def_use_pairs(input_file):
    with open(input_file, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    pairs = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("Definition:"):
            def_line = lines[i]
            use_line = lines[i+1] if i+1 < len(lines) and lines[i+1].startswith("Use:") else None
            if use_line:
                def_addr = parse_address(def_line)
                use_addr = parse_address(use_line)
                # Convert to int for sorting
                def_int = int(def_addr, 16)
                pairs.append((def_int, def_addr, use_addr))
                i += 2
            else:
                i += 1
        else:
            i += 1

    # Sort by the integer value of the definition address
    pairs.sort(key=lambda x: x[0])
    return pairs

def main():
    gdbmi = connect_gdb()
    # continue_execution(gdbmi)
    # Load and sort definition-use pairs
    pairs = sort_def_use_pairs('def_use.txt')

    # We'll set watchpoints on the first 4 definition addresses
    # Adjust if you have fewer than 4 pairs
    watch_limit = min(len(pairs), 4)
    watchpoints_map = {}  # Maps watchpoint bkptno to (def_addr, use_addr)
    # continue_execution(gdbmi)
    for idx in range(watch_limit):
        def_int, def_addr, use_addr = pairs[idx]
        # print(def_int)
        print(f"Setting watchpoint at def {def_addr}, to be triggered at use {use_addr}")

        w_bkptno = set_watchpoint(gdbmi, def_addr)
        if w_bkptno is not None:
            watchpoints_map[w_bkptno] = (def_addr, use_addr)

    continue_execution(gdbmi)
    try:
        while True:
            # Increase timeout or handle exceptions
            try:
                responses = gdbmi.get_gdb_response(timeout_sec=5, raise_error_on_timeout=False)
                print(responses)
            except GdbTimeoutError:
                # No response within 5 seconds. Could print a message or continue silently
                responses = []

            for response in responses:
                if response['type'] == 'notify' and response['message'] == 'stopped':
                    reason = response['payload'].get('reason', '')
                    bkptno = response['payload'].get('bkptno', '')
                    if reason == 'watchpoint-trigger':
                        print(f"Watchpoint {bkptno} triggered.")
                        if bkptno in watchpoints_map:
                            def_addr, use_addr = watchpoints_map[bkptno]
                            print(f"Watch triggered at def {def_addr}, setting breakpoint at use {use_addr}")
                            set_breakpoint(gdbmi, use_addr)
                            continue_execution(gdbmi)

                    elif reason == 'breakpoint-hit':
                        addr = response['payload'].get('frame', {}).get('addr', '')
                        func = response['payload'].get('frame', {}).get('func', '')
                        print(f"Breakpoint hit at {func} ({addr})")
                        continue_execution(gdbmi)

    except KeyboardInterrupt:
        print("Stopping GDB session.")
    finally:
        gdbmi.exit()

if __name__ == '__main__':
    main()