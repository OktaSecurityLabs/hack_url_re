from typing import List, Union, Dict
import itertools


SYMBOL_START = b'\xaa'
SYMBOL_END = b'\xdd'


def parse_encoded_symbols(bb: bytes) -> List[Union[str, int]]:
    elements = []
    current_element_chars = []
    in_symbol = False
    for cc in bb:
        if cc == ord(SYMBOL_START):
            in_symbol = True
            if current_element_chars:
                elements.append(bytes(current_element_chars).decode('utf8'))
                current_element_chars.clear()
        elif cc == ord(SYMBOL_END):
            assert in_symbol, "parse error"
            in_symbol = False
            elements.append(int(b'0x' + bytes(current_element_chars), base=16))
            current_element_chars.clear()
        else:
            current_element_chars.append(cc)

    if current_element_chars:
        elements.append(bytes(current_element_chars).decode('utf8'))

    return elements


def concretizations(bb: bytes, mappings: Dict[int, List[str]]) -> str:
    elts = [mappings.get(k,[k]) for k in parse_encoded_symbols(bb)]
    return (''.join(xx) for xx in itertools.product(*elts))
