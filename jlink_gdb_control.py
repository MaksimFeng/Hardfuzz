import subprocess
import time
import sys

def start_jlink_gdb_server():
    """
    Start the JLink GDB Server and return the subprocess handle.

    If '-nohalt' is supported by your version of JLinkGDBServer, it will
    keep the target running instead of halting on connect.
    """
    jlink_command = [
        'JLinkGDBServer',
        '-device', 'ATSAM3X8E',
        '-if', 'JTAG',
        '-speed', '4000',
        '-port', '2331',
        '-nohalt',        # Uncomment if your JLink version supports this
    ]

    # Start the JLink GDB Server process
    jlink_process = subprocess.Popen(
        jlink_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    # Give the server a little time to initialize
    time.sleep(2)
    print("JLink GDB Server started.")
    return jlink_process

if __name__ == '__main__':
    jlink_process = start_jlink_gdb_server()
    try:
        # Continuously read & print the JLink server output
        while True:
            output_line = jlink_process.stdout.readline()
            if not output_line:
                # The process ended or no more output
                break
            sys.stdout.write(output_line)
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("Stopping JLink GDB Server (Ctrl + C).")

    finally:
        # Terminate JLink GDB Server
        jlink_process.terminate()
