import serial
import time
import json
import random
import string

def generate_random_json():
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

def wait_for_request(ser):
    # Check if 'A' is already in the buffer
    data = ser.read(ser.in_waiting)
    # print(data)
    if b'A' in data:
        return
    while True:
        if ser.in_waiting > 0:
            data = ser.read(ser.in_waiting)
            if b'A' in data:
                return
        time.sleep(0.01)

def send_test_case(ser, test_case_json):
    test_case_bytes = test_case_json.encode('utf-8')
    wait_for_request(ser)
    data_length = len(test_case_bytes)
    # print(data_length)
    ser.write(data_length.to_bytes(4, byteorder='little'))
    ser.write(test_case_bytes)

    response = read_response(ser)
    # print(response)
    return response

def read_response(ser):
    response = b''

    start_time = time.time()
    timeout = 2  # seconds

    while True:
        if ser.in_waiting > 0:
            response += ser.read(ser.in_waiting)
            processed_response, remaining_data = process_incoming_data(response)
            if processed_response is not None:
                ser.flushInput()
                ser.write(remaining_data)
                return processed_response
        if time.time() - start_time > timeout:
            break
        time.sleep(0.01)#emmmmmmm
    return response

def process_incoming_data(data):
    if len(data) >= 1:
        response_code = data[0]
        if response_code != 0:
            if len(data) >= 4:
                return data[:4], data[4:]
        else:
            if len(data) >= 5:
                num_bytes = int.from_bytes(data[1:5], byteorder='little')
                total_length = 1 + 4 + num_bytes
                if len(data) >= total_length:
                    # Check for extra 'A' at the end
                    remaining_data = data[total_length:]
                    return data[:total_length], remaining_data
    return None, b''

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
        num_bytes = int.from_bytes(response[1:5], byteorder='little')
        json_data = response[5:5+num_bytes].decode('utf-8')
        print(f"Received JSON data ({num_bytes} bytes): {json_data}")

def main():
    ser = serial.Serial('/dev/ttyACM1', 38400, timeout=0)
    time.sleep(2)  

    try:
        while True:
            test_case_json = generate_random_json()
            print(f"Sending test case: {test_case_json}")

            response = send_test_case(ser, test_case_json)
            process_response(response)

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("Stopping fuzzing.")
    finally:
        ser.close()

if __name__ == '__main__':
    main()
