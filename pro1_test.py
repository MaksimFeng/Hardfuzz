import serial
import time
import struct
import json

SERIAL_PORT = "/dev/ttyACM1"  
BAUD_RATE = 38400

ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=5)

def wait_for_ready_signal():
    """Wait for Arduino to send 'A' indicating it's ready."""
    while True:
        if ser.in_waiting:
            response = ser.read(1)
            if response == b'A':  
                print("[INFO] Arduino is ready")
                return

def send_payload(payload):
    """Send a payload to the Arduino, prefixed with its length."""
    json_data = json.dumps(payload)
    json_bytes = json_data.encode('utf-8')
    length = len(json_bytes)

    if length > 2048:
        print("[ERROR] Payload too large")
        return

    ser.write(struct.pack("<I", length))
    time.sleep(0.1)
    ser.flush()
    time.sleep(0.1)
    ser.write(json_bytes)
    time.sleep(0.1)
    ser.flush()

    response_code = ser.read(1)
    if not response_code:
        print("[ERROR] No response received")
        return

    if response_code != b'\x00':  # Non-zero means error
        print(f"[ERROR] Arduino rejected JSON with code: {ord(response_code)}")
    else:
        response_length_bytes = ser.read(4)
        response_length = struct.unpack("<I", response_length_bytes)[0]

        response_json = ser.read(response_length).decode('utf-8')
        print("[SUCCESS] Arduino Response:", response_json)

valid_data = {
    "test": 1,
    "valid": True,
}
wait_for_ready_signal()
print("\nSending valid JSON...")
send_payload(valid_data)

time.sleep(2)  # Wait before sending the next payload

invalid_data = b'{"temperature": 23.5, "humidity": 60, "status": '  
wait_for_ready_signal()
print("\nSending invalid JSON...")
# ser.write(struct.pack("<I", len(invalid_data)))  
# ser.write(invalid_data)  

# error_response = ser.read(1)
# if error_response and error_response != b'\x00':
#     print(f"[ERROR] Arduino detected invalid JSON with code: {ord(error_response)}")
# else:
#     print("[ERROR] No response received or unexpected behavior.")

ser.close()
