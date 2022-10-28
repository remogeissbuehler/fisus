from typing import Iterable

def glen(it: Iterable):
    return sum(1 for i in it)