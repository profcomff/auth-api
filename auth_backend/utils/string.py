import random
import string
from typing import Iterable


def random_string(length: int = 32) -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(length)])


def concantenate_strings(strings: Iterable[str]):
    '''Объединяет переданные строки в одну строку, ставя пробелы между ними'''
    return ' '.join(strings).strip()
