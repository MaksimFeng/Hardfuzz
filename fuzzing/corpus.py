from dataclasses import dataclass

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
    burn_in: int = 5

    def compute_weight(self, total_hit_blocks: int, total_corpus_entries: int):
        if self.burn_in:
            self.weight = self.burn_in
        else:
            self.weight = 1.0

    def __str__(self) -> str:
        return (f'{self.fname}, depth={self.depth}, hit_blocks={self.hit_blocks}, '
                f'num_fuzzed={self.num_fuzzed}, childs={self.num_childs}, weight={self.weight}, burn_in={self.burn_in}')
