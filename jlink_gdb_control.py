import subprocess
import time

def start_jlink_gdb_server():
    jlink_command = [
        'JLinkGDBServer',       # Path to the JLinkGDBServer executable
        '-device', 'ATSAM3X8E', # Device name for Arduino Due's MCU
        '-if', 'JTAG',          # Interface type (JTAG or SWD)
        '-speed', '4000',       # Communication speed
        '-port', '2331'         # GDB server port
    ]

    # Start the JLink GDB Server
    jlink_process = subprocess.Popen(
        jlink_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    # Wait for the GDB Server to initialize
    time.sleep(2)
    print("JLink GDB Server started.")
    return jlink_process

if __name__ == '__main__':
    jlink_process = start_jlink_gdb_server()
    try:
        # Keep the script running to maintain the GDB server
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping JLink GDB Server.")
    finally:
        jlink_process.terminate()