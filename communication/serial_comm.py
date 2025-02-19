import time
import logging as log
import serial

def wait_for_request(ser, timeout=5):
    """
    Wait for the board to send the character 'A' (ASCII 65) to indicate
    it's ready for input. Times out after 'timeout' seconds if 'A' is not received.
    """
    start_time = time.time()
    buffer = b''

    while True:
        # Read all available data
        data = ser.read_all()
        if data:
            log.info(f"Received data: {data}")
            buffer += data
            # If 'A' is in the buffer, we can return
            if b'A' in buffer:
                log.info("Received request (A) from the board.")
                return
        else:
            log.debug("not find A")
            return
        # Check for timeout
        # if time.time() - start_time > timeout:
        #     log.warning("Timeout waiting for 'A' from the board.")
        #     raise RuntimeError("BoardStuckTimeout")
        #     # return

        time.sleep(0.01)


def process_incoming_data(data):
    if len(data) >= 1:
        response_code = data[0]
        # Non-zero response_code is an error code
        if response_code != 0:
            return data[:1], data[1:]
        else:
            # Zero response_code indicates potential JSON data
            if len(data) >= 5:
                num_bytes = int.from_bytes(data[1:5], byteorder='little')
                total_length = 1 + 4 + num_bytes
                if len(data) >= total_length:
                    remaining_data = data[total_length:]
                    return data[:total_length], remaining_data
    return None, b''


def read_response(ser, timeout=2):
    """
    Read a response from the board, returning a processed response
    if valid data is found (error code or JSON).
    Otherwise, returns whatever partial data it captured by timeout.
    """
    response = b''
    start_time = time.time()

    while True:
        if ser.in_waiting > 0:
            chunk = ser.read(ser.in_waiting)
            log.info(f"Received data: {chunk}")
            response += chunk
            processed_response, remaining_data = process_incoming_data(response)
            log.debug(f"Processed response: {processed_response}")
            if processed_response is not None:
                return processed_response
            # If not enough data yet, keep reading
        if time.time() - start_time > timeout:
            break
        time.sleep(0.01)
    log.debug(f"Returning partial response: {response}")
    return response


def process_response(response):
    if not response:
        log.warning("No response from the board.")
        return

    response_code = response[0]
    if response_code != 0:
        # Non-zero response code => error
        error_code = response_code
        log.error(f"Received error code: {error_code}")
    else:
        # The first 5 bytes: 0 + 4-byte length
        num_bytes = int.from_bytes(response[1:5], byteorder='little')
        # Check length correctness
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
    """
    Sends a test case to the board. First waits for request 'A',
    then sends length + data, then reads a response.
    """
    log.info("Waiting for the board to request input...")
    wait_for_request(ser, timeout=5)

    # If you need to bail out if wait_for_request never saw 'A', do that here
    # e.g. check logs or raise an exception

    log.info("Sending test case to the board.")
    data_length = len(test_case_bytes)
    # log.info(f"Sending {data_length} bytes of test data: {test_case_bytes}")
    # Send length first (4 bytes, little-endian)
    ser.write(data_length.to_bytes(4, byteorder='little'))
    # Send the actual data
    ser.write(test_case_bytes)
    log.info(f"Sent {data_length} bytes of data: {test_case_bytes}")
    ser.flush()
    # Read the response
    response = read_response(ser, timeout=2)
    log.info(f"Received response: {response}")
    #this part
    return response
