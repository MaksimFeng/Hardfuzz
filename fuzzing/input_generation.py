# input_generation.py
import os
import random
import logging as log
from typing import List

from .corpus import CorpusEntry
import _pylibfuzzer

class InputGeneration:
    def __init__(self, output_directory: str, seeds_directory: str | None = None,
                 max_input_length: int = 1024, libfuzzer_so_path: str | None = None):
        if libfuzzer_so_path is None:
            libfuzzer_so_path = os.path.join(
                os.path.dirname(__file__),
                '../fuzz_wrappers/libfuzzerSrc/libfuzzer-mutator.so'
            )
            os.environ['libfuzzer_mutator_so_path'] = libfuzzer_so_path

        self.max_input_length = max_input_length
        self.corpus_directory = os.path.join(output_directory, 'corpus')
        os.makedirs(self.corpus_directory, exist_ok=True)

        if seeds_directory is not None and not os.path.exists(seeds_directory):
            raise Exception(f'{seeds_directory=} does not exist.')

        self.corpus: List[CorpusEntry] = []
        self.current_base_input_index: int = -1
        self.retry_corpus_input_index: int = 0
        self.total_hit_blocks = 0

        if seeds_directory:
            self.add_seeds(seeds_directory)

        if len(self.corpus) == 0:
            self.add_corpus_entry(b'{"test":123,"valid":true}', 0, 0)

        _pylibfuzzer.initialize(self.max_input_length)

    def add_seeds(self, seeds_directory: str) -> None:
        for filename in sorted(os.listdir(seeds_directory)):
            filepath = os.path.join(seeds_directory, filename)
            if not os.path.isfile(filepath):
                continue
            with open(filepath, 'rb') as f:
                seed = f.read()
                if len(seed) > self.max_input_length:
                    log.warning(
                        f'Seed {filepath} was not added to the corpus because '
                        f'the seed length ({len(seed)}) was too large {self.max_input_length=}.'
                    )
                    continue
                if seed not in [entry.content for entry in self.corpus]:
                    self.add_corpus_entry(seed, 0, 0)

    def add_corpus_entry(self, input: bytes, address: int, timestamp: int) -> CorpusEntry:
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
        # [NEW LOGIC] => If coverage is new, let's set burn_in=5 or 10
        # so that next call to choose_new_baseline_input() might pick it soon.
        entry.burn_in = 5
        
        self.corpus.append(entry)
        return entry

    def choose_new_baseline_input(self):
        energy_sum = 0
        cum_energy = []
        for i in self.corpus:
            i.compute_weight(self.total_hit_blocks, len(self.corpus))
            energy_sum += i.weight
            cum_energy.append(energy_sum)
        # Weighted pick from corpus
        self.current_base_input_index = random.choices(range(len(cum_energy)), cum_weights=cum_energy).pop()
        chosen_entry = self.corpus[self.current_base_input_index]
        chosen_entry.num_fuzzed += 1
        if chosen_entry.burn_in:
            chosen_entry.burn_in -= 1

    def get_baseline_input(self) -> bytes:
        return self.corpus[self.current_base_input_index].content

    def generate_input(self) -> bytes:
        if self.retry_corpus_input_index < len(self.corpus):
            input_data = self.corpus[self.retry_corpus_input_index].content
            self.retry_corpus_input_index += 1
            return input_data
        generated_inp = _pylibfuzzer.mutate(self.corpus[self.current_base_input_index].content)
        return generated_inp

    def report_address_reached(self, current_input: bytes, address: int, timestamp: int) -> None:
        self.total_hit_blocks += 1
        for i in self.corpus:
            if i.content == current_input:
                i.hit_blocks += 1
                return
        self.retry_corpus_input_index = 0
        entry = self.add_corpus_entry(current_input, address, timestamp)
        entry.hit_blocks += 1
        log.debug(f'New Corpus entry {current_input!r}')
