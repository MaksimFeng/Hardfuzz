import serial
import time
import json
import random
import string

def generate_random_json():
    # Generate random JSON data
    data = {}
    for _ in range(random.randint(1, 10)):
        key = ''.join(random.choices(string.ascii_letters, k=5))
        value = random.choice([
            random.randint(-1000, 1000),
            random.uniform(-1000, 1000),
            ''.join(random.choices(string.ascii_letters + string.digits, k=10)),
            None,
            True,
            False
        ])
        data[key] = value
    return json.dumps(data)

def send_test_case(ser, test_case_json):
    test_case_bytes = test_case_json.encode('utf-8')

    # Wait for the board to request new input
    while True:
        if ser.in_waiting > 0:
            request = ser.read(1)
            if request == b'A':
                break

    # Send the length of the data (4 bytes, little-endian)
    data_length = len(test_case_bytes)
    ser.write(data_length.to_bytes(4, byteorder='little'))

    # Send the actual JSON data
    ser.write(test_case_bytes)

    # Read response
    time.sleep(0.1)
    response = ser.read_all()

    return response

def process_response(response):
    if not response:
        print("No response from the board.")
        return

    response_code = response[0]
    if response_code != 0:
        # Error code received
        error_code = int.from_bytes(response[:4], byteorder='little')
        print(f"Received error code: {error_code}")
    else:
        # Success code received
        num_bytes = int.from_bytes(response[1:5], byteorder='little')
        json_data = response[5:5+num_bytes].decode('utf-8')
        print(f"Received JSON data ({num_bytes} bytes): {json_data}")

def main():
    # Initialize serial communication
    ser = serial.Serial('/dev/ttyACM0', 38400, timeout=1)
    time.sleep(2)  # Wait for serial connection to initialize

    try:
        while True:
            test_case_json = generate_random_json()
            print(f"Sending test case: {test_case_json}")

            response = send_test_case(ser, test_case_json)
            process_response(response)

            # Add a delay between test cases if needed
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("Stopping fuzzing.")
    finally:
        ser.close()

if __name__ == '__main__':
    main()
