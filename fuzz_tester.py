import serial
import time
import json
import random
import string
import pdb
import os
import _py
import _pylibfuzzer


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

def right_json():
    data = {}
    num_entries = random.randint(1, 3)  
    for _ in range(num_entries):
        key = ''.join(random.choices(string.ascii_letters, k=5))
        value_type = random.choice(['int', 'float', 'string', 'bool'])
        if value_type == 'int':
            value = random.randint(-100, 100)
        elif value_type == 'float':
            value = round(random.uniform(-100, 100), 2)
        elif value_type == 'string':
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
        elif value_type == 'bool':
            value = random.choice([True, False])
        data[key] = value
    return json.dumps(data)



def right_number():
    return json.dumps({"test": 123, "valid": True})




def wait_for_request(ser):
    while True:
        data = ser.read(1)
        if data == b'A':
            return
        time.sleep(0.01)


def send_test_case(ser, test_case_json):
    test_case_bytes = test_case_json.encode('utf-8')
    wait_for_request(ser)
    data_length = len(test_case_bytes)
    # print(data_length)
    ser.write(data_length.to_bytes(4, byteorder='little'))
    ser.write(test_case_bytes)
    print(f"Sent {data_length} bytes of data.")
    print(f"Data: {test_case_json}")
    # print("---")
    # print()
    # print("---")
    response = read_response(ser)
    print(response)
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
                return processed_response  
            
        if time.time() - start_time > timeout:
            break
        time.sleep(0.01)
    return response


def process_incoming_data(data):
    if len(data) >= 1:
        response_code = data[0]
        if response_code != 0:
            # Error response is just one byte
            return data[:1], data[1:]
        else:
            if len(data) >= 5:
                num_bytes = int.from_bytes(data[1:5], byteorder='little')
                total_length = 1 + 4 + num_bytes
                if len(data) >= total_length:
                    remaining_data = data[total_length:]
                    return data[:total_length], remaining_data
    return None, b''

def process_response(response):
    if not response:
        print("No response from the board.")
        return

    response_code = response[0]
    if response_code != 0:
        error_code = response_code
        print(f"Received error code: {error_code}")
    else:
        num_bytes = int.from_bytes(response[1:5], byteorder='little')
        print(f"num_bytes: {num_bytes}, len(response): {len(response)}")
        if len(response) < 5 + num_bytes:
            print("Incomplete response data.")
            print(f"Response: {response.hex()}")
            return
        data_to_decode = response[5:5+num_bytes]
        try:
            json_data = data_to_decode.decode('utf-8')
        except UnicodeDecodeError as e:
            print(f"UnicodeDecodeError: {e}")
            print(f"Data to decode (hex): {data_to_decode.hex()}")
            return
        print(f"Received JSON data ({num_bytes} bytes): {json_data}")


def main():
    ser = serial.Serial('/dev/ttyACM1', 38400, timeout=1)  # Set timeout to 1 second
    time.sleep(2)  

    try:
        while True:
            test_case_json = generate_random_json()
            # test_case_json = right_json()
            # test_case_json = right_number()
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
