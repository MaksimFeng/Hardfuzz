from __future__ import annotations

import configparser
import multiprocessing as mp
import signal
import logging as log
import time
import struct
from abc import abstractmethod
from typing import Any

import serial

class ConnectionBaseClass(mp.Process):
    """
    Base class that runs in its own Process to handle SUT I/O. 
    Override connect(), connect_async(), wait_for_input_request(),
    send_input(), and disconnect() in a subclass.
    """

    def __init__(
        self,
        stop_responses: mp.Queue[tuple[str, Any]],
        SUTConnection_config: configparser.SectionProxy,
        inputs: mp.Queue[bytes],
        reset_sut
    ):
        super().__init__()
        self.stop_responses = stop_responses
        self.SUTConnection_config = SUTConnection_config
        self.inputs = inputs
        self.reset_sut_function = reset_sut

    def start(self):
        # Optionally do a "connect" while the SUT is halted, 
        # so we can fail early if the port is invalid, etc.
        try:
            self.connect(self.SUTConnection_config)
        except Exception as e:
            log.warning(f"Initial connect() failed: {e}")
        
        # Now actually start the subprocess
        super().start()
        # Give the process some time to spin up fully
        time.sleep(1)

    def run(self) -> None:
     
        signal.signal(signal.SIGUSR1, self.on_exit)

        # If certain connections require the target to run, do it here
        self.connect_async()

        while True:
            # 1) Wait for the target to say it's ready (e.g. sending 'A')
            self.wait_for_input_request()
            # 2) Notify the main process that we want fuzz data now
            self.stop_responses.put(('input request', ''))

            # 3) Fetch the next fuzz input from our queue (blocking)
            fuzz_input = self.inputs.get(block=True)
            # 4) Send it
            self.send_input(fuzz_input)

    def reset_sut(self):
        """
        Optional. If you want to e.g. send a GDB command 
        or toggle reset lines, do it here.
        """
        self.reset_sut_function()

    def on_exit(self, signum: Any, frame: Any) -> None:
        """
        Cleanly disconnect and exit when we receive SIGUSR1.
        """
        self.disconnect()
        exit(0)

    @abstractmethod
    def connect(self, SUTConnection_config: configparser.SectionProxy) -> None:
        """Connect to the SUT while it is halted (if applicable)."""
        ...

    @abstractmethod
    def connect_async(self) -> None:
        """Connect to the SUT asynchronously (while running)."""
        ...

    @abstractmethod
    def send_input(self, fuzz_input: bytes) -> None:
        """Send fuzz_input to the SUT via your protocol."""
        ...

    @abstractmethod
    def wait_for_input_request(self) -> None:
        """
        Block until the SUT indicates it wants data 
        (e.g. by sending the ASCII character 'A').
        """
        ...

    def disconnect(self) -> None:
        """Free any resources, e.g. close the serial port."""
        pass


class SerialConnection(ConnectionBaseClass):
    """
    A concrete implementation of ConnectionBaseClass 
    that uses the serial port.
    """

    def connect(self, SUTConnection_config: configparser.SectionProxy) -> None:
        # Read config
        port = SUTConnection_config['port']
        baud = SUTConnection_config.getint('baud_rate', 115200)
        to   = SUTConnection_config.getint('serial_timeout', 1)

        # Open serial
        self.serial = serial.Serial(port, baud, timeout=to)
        self.serial.reset_input_buffer()
        
        # Optionally reset the SUT so it starts running 
        # and eventually prints 'A' to request input
        self.reset_sut()

        log.info(f"Established connection on {self.serial.name} at {baud} baud.")

    def connect_async(self) -> None:
        """
        If your SUT needs to be running (i.e., not halted in GDB) 
        to complete the handshake, do nothing special 
        or handle any 'run' commands here.
        """
        pass

    def wait_for_input_request(self) -> None:
        """
        Blocks until the board sends 'A'.
        For safety, we read everything available 
        and look for ASCII 65 in the buffer.
        """
        buffer = b''
        while True:
            chunk = self.serial.read_all()
            if chunk:
                log.debug(f"Received chunk: {chunk}")
                buffer += chunk
                # Check if 'A' (ASCII 65) is in the data
                if b'A' in buffer:
                    log.info("Received request (A) from the board.")
                    return
            time.sleep(0.01)

    def send_input(self, fuzz_input: bytes) -> None:
        """
        Our protocol: 
          1) Send 4-byte little-endian length 
          2) Then send the fuzz data
        """
        import struct
        log.debug(f"Sending fuzz input of length {len(fuzz_input)}.")
        length_bytes = struct.pack("<I", len(fuzz_input))
        
        self.serial.write(length_bytes)
        self.serial.write(fuzz_input)
        self.serial.flush()
        log.info(f"Sent {len(fuzz_input)} bytes to SUT.")

    def disconnect(self) -> None:
        if hasattr(self, 'serial'):
            self.serial.close()
            log.info("Closed serial port connection.")



















#----


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
