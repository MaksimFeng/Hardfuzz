import time
import logging as log
import serial

def wait_for_request(ser):
    while True:
        data = ser.read(1)
        if data == b'A':
            return
        time.sleep(0.01)

def process_incoming_data(data):
    if len(data) >= 1:
        response_code = data[0]
        if response_code != 0:
            return data[:1], data[1:]
        else:
            if len(data) >= 5:
                num_bytes = int.from_bytes(data[1:5], byteorder='little')
                total_length = 1 + 4 + num_bytes
                if len(data) >= total_length:
                    remaining_data = data[total_length:]
                    return data[:total_length], remaining_data
    return None, b''

def read_response(ser):
    response = b''
    start_time = time.time()
    timeout = 2
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

def process_response(response):
    if not response:
        log.warning("No response from the board.")
        return
    response_code = response[0]
    if response_code != 0:
        error_code = response_code
        log.error(f"Received error code: {error_code}")
    else:
        num_bytes = int.from_bytes(response[1:5], byteorder='little')
        if len(response) < 5 + num_bytes:
            log.error("Incomplete response data.")
            log.debug(f"Response: {response.hex()}")
            return
        data_to_decode = response[5:5+num_bytes]
        try:
            json_data = data_to_decode.decode('utf-8')
            log.info(f"Received JSON data ({num_bytes} bytes): {json_data}")
        except UnicodeDecodeError as e:
            log.error(f"UnicodeDecodeError: {e}")
            log.debug(f"Data to decode (hex): {data_to_decode.hex()}")

def send_test_case(ser, test_case_bytes):
    wait_for_request(ser)
    data_length = len(test_case_bytes)
    ser.write(data_length.to_bytes(4, byteorder='little'))
    ser.write(test_case_bytes)
    log.info(f"Sent {data_length} bytes of data.")
    log.info(f"Data: {test_case_bytes}")
    response = read_response(ser)
    return response
