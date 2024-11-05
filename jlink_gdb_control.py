import subprocess
import time

def start_jlink_gdb_server():
    jlink_command = [
        'JLinkGDBServer',       
        '-device', 'ATSAM3X8E', 
        '-if', 'JTAG',          
        '-speed', '4000',       
        '-port', '2331'         
    ]

    # Start the JLink GDB Server
    jlink_process = subprocess.Popen(
        jlink_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    time.sleep(2)
    print("JLink GDB Server started.")
    return jlink_process

if __name__ == '__main__':
    jlink_process = start_jlink_gdb_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping JLink GDB Server.")
    finally:
        jlink_process.terminate()