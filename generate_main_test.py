from __future__ import annotations
# //解释器在注解中使用的类名按字符串处理
from dataclasses import dataclass
# //引入dataclass装饰器，帮助简化类的定义，自动添加初始化方法和其他方法
import serial
import time
import json
import random
import string
import logging as log
import os
import _pylibfuzzer

# Set up logging
log.basicConfig(level=log.INFO)

@dataclass
class CorpusEntry:
    content: bytes
    fname: str
    origin: int
    depth: int
    hit_blocks: int = 0
    num_fuzzed: int = 0
    num_childs: int = 0
    weight: float = 1
    burn_in: int = 5 # Number of times to retry this input before moving on

    def compute_weight(self, total_hit_blocks: int, total_corpus_entries: int):
        self.weight = 1.0

        # Adapted from AFL 
        # if self.num_fuzzed:
        #     self.weight *= math.log10(self.num_fuzzed) + 1

        # if self.num_childs:
        #     self.weight *= self.num_childs / float(total_corpus_entries) + 1

        # if self.hit_blocks:
        #     self.weight *= self.hit_blocks / float(total_hit_blocks) + 1

        # if self.depth:
        #     self.weight *= math.log(self.depth) + 1

        if self.burn_in:
            self.weight *= self.burn_in

    def __str__(self) -> str:
        return f'{self.fname}, depth={self.depth}, hit_blocks={self.hit_blocks}, num_fuzzed={self.num_fuzzed}, childs={self.num_childs}, weight={self.weight}, burn_in={self.burn_in}'

class InputGeneration:

    def __init__(
            self,
            output_directory: str,
            seeds_directory: str | None = None,
            max_input_length: int = 1024,
            libfuzzer_so_path: str | None = None
        ):
        if libfuzzer_so_path is None:
            libfuzzer_so_path = os.path.join(
                os.path.dirname(__file__),
                'fuzz_wrappers/libfuzzerSrc/libfuzzer-mutator.so'
            )
            # _pylibfuzzer reads this env var to know where
            # libfuzzer-mutator.so is located.
            os.environ['libfuzzer_mutator_so_path'] = libfuzzer_so_path

        # Maximum length of generated inputs in bytes.
        self.max_input_length = max_input_length

        # Corpus entries are stored on disk in this directory.
        self.corpus_directory = os.path.join(output_directory, 'corpus')
        os.makedirs(self.corpus_directory, exist_ok=True)

        if not os.path.exists(libfuzzer_so_path):
            raise Exception(f'{libfuzzer_so_path=} does not exist.')

        if seeds_directory is not None:
            if not os.path.exists(seeds_directory):
                raise Exception(f'{seeds_directory=} does not exist.')

        # List to store corpus entries.
        self.corpus: list[CorpusEntry] = []

        # For the initialization phase,tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt
        # The currently selected base input
        self.current_base_input_index: int = -1

        # Initialize retry_corpus_input_index to 0
        self.retry_corpus_input_index: int = 0
        # 初始化语料库列表、当前基准输入索引（-1表示未选择），以及重试索引和总命中块数。
        # For statistic purposes
        self.total_hit_blocks = 0

        if seeds_directory:
            self.add_seeds(seeds_directory)

        if len(self.corpus) == 0:
            self.add_corpus_entry(b'{"test":123,"valid":true}', 0, 0)  # Default JSON seed

        # Setup libFuzzer object.
        _pylibfuzzer.initialize(self.max_input_length)

    def add_seeds(self, seeds_directory: str) -> None:
        """Add each seed in seeds_directory to the corpus. 
        """
        for filename in sorted(os.listdir(seeds_directory)):
            filepath = os.path.join(seeds_directory, filename)
            if not os.path.isfile(filepath):
                continue
            with open(filepath, 'rb') as f:
                seed = f.read()
                if len(seed) > self.max_input_length:
                    log.warning(
                        f'Seed {filepath} was not added to the corpus '
                        f'because the seed length ({len(seed)}) was too large '
                        f'{self.max_input_length=}.'
                    )
                    continue
                log.debug(f'Seed {filepath} added.')
                if seed not in [entry.content for entry in self.corpus]:
                    self.add_corpus_entry(seed, 0, 0)

    def add_corpus_entry(self, input: bytes, address: int, timestamp: int) -> CorpusEntry:
        # 此方法将输入添加到语料库，并返回新创建的CorpusEntry对象。
        filepath = os.path.join(
            self.corpus_directory,
            f'id:{str(len(self.corpus))},orig:{self.current_base_input_index},addr:{hex(address)},time:{timestamp}'
        )
        with open(filepath, 'wb') as f:
            f.write(input)

        depth = 0
        if self.current_base_input_index >= 0:
            depth = self.corpus[self.current_base_input_index].depth + 1
            self.corpus[self.current_base_input_index].num_childs += 1

        entry = CorpusEntry(input, filepath, self.current_base_input_index, depth)
        self.corpus.append(entry)

        return entry

    def choose_new_baseline_input(self):
        # if self.retry_corpus_input_index > 0:
        #     self.retry_corpus_input_index = 0
        energy_sum = 0
        cum_energy = []
        for i in self.corpus:
            i.compute_weight(self.total_hit_blocks, len(self.corpus))
            energy_sum += i.weight
            cum_energy.append(energy_sum)
        # Draw new corpus entry according to energy
        self.current_base_input_index = random.choices(range(len(cum_energy)), cum_weights=cum_energy).pop()

        chosen_entry = self.corpus[self.current_base_input_index]
        chosen_entry.num_fuzzed += 1
        if chosen_entry.burn_in:
            chosen_entry.burn_in -= 1

    def get_baseline_input(self) -> bytes:
        return self.corpus[self.current_base_input_index].content

    def generate_input(self) -> bytes:
        # After a reset, we first try all corpus files again
        if self.retry_corpus_input_index < len(self.corpus):
            input = self.corpus[self.retry_corpus_input_index].content
            self.retry_corpus_input_index += 1
            return input

        generated_inp = _pylibfuzzer.mutate(self.corpus[self.current_base_input_index].content)
        return generated_inp

    def report_address_reached(self, current_input: bytes, address: int, timestamp: int) -> None:

        self.total_hit_blocks += 1
        # Check if current_input is already in the corpus
        for i in self.corpus:
            if i.content == current_input:
                i.hit_blocks += 1
                return

        # A new path was discovered, so try all corpus files again
        self.retry_corpus_input_index = 0
        entry = self.add_corpus_entry(current_input, address, timestamp)
        entry.hit_blocks += 1
        log.debug(f'New Corpus entry {current_input!r}')

# Functions for serial communication and test case handling
def wait_for_request(ser):
    while True:
        data = ser.read(1)
        if data == b'A':
            return
        time.sleep(0.01)

def send_test_case(ser, test_case_bytes):
    wait_for_request(ser)
    data_length = len(test_case_bytes)
    ser.write(data_length.to_bytes(4, byteorder='little'))
    ser.write(test_case_bytes)
    log.info(f"Sent {data_length} bytes of data.")
    log.info(f"Data: {test_case_bytes}")
    response = read_response(ser)
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
            # Analyze json_data if necessary
        except UnicodeDecodeError as e:
            log.error(f"UnicodeDecodeError: {e}")
            log.debug(f"Data to decode (hex): {data_to_decode.hex()}")

def main():
    # Adjust the serial port and baud rate as per your configuration
    ser = serial.Serial('/dev/ttyACM0', 38400, timeout=1)
    time.sleep(2)  # Wait for the serial connection to initialize

    output_directory = 'output'
    seeds_directory = 'seeds'  # Ensure this directory contains valid JSON seed files

    input_gen = InputGeneration(
        output_directory=output_directory,
        seeds_directory=seeds_directory,
    )

    try:
        while True:
            input_gen.choose_new_baseline_input()
            test_case_bytes = input_gen.generate_input()

            # Attempt to decode the generated input as UTF-8
            try:
                test_case_str = test_case_bytes.decode('utf-8')
                # Optionally, attempt to parse as JSON
                # json_data = json.loads(test_case_str)
                # If parsing is successful, proceed to send the test case
            except UnicodeDecodeError:
                # If decoding fails, skip this input
                log.debug("Failed to decode input as UTF-8, skipping.")
                continue

            log.info(f"Sending test case: {test_case_str}")
            response = send_test_case(ser, test_case_bytes)
            process_response(response)

            timestamp = int(time.time())
            # Since we don't have actual addresses, we'll use a placeholder
            input_gen.report_address_reached(test_case_bytes, address=0, timestamp=timestamp)

            time.sleep(0.1)
    except KeyboardInterrupt:
        log.info("Stopping fuzzing.")
    finally:
        ser.close()

if __name__ == '__main__':
    main()
