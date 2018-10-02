import z3

from pdb import set_trace

import string
import toolz
import enum
import logging
from typing import Iterable, Tuple, Dict, Sequence

from . import parsing
from .parsing import (PToken, EMPTY, CHAR, DOT, STAR, BAR, CONCAT, GROUP, BACKREF, CARET, DOLLAR)
from .abstracting import SYMBOL_START, SYMBOL_END


logger = logging.getLogger(__name__)


class CharSet(enum.Enum):
    WORD = enum.auto()  # alphanumeric + _
    META = enum.auto()
    OTHER = enum.auto()

charsets = {
    CharSet.WORD: frozenset(string.ascii_letters + string.digits + '_'),
    CharSet.META: frozenset('./'),
}


def remove_path(r):
    """Keep only what comes before the third slash.
    Only applies to a toplevel CONCAT or GROUP, and must be after combining CONCATs
    and combining CHARs"""
    ty = r[0]

    if ty == PToken.CONCAT:
        slash_cnt = 0
        new_r = [PToken.CONCAT]
        for elt in r[1:]:
            if elt[0] == PToken.CHAR:
                for ii, cc in enumerate(elt[1]):
                    if cc == '/':
                        slash_cnt += 1
                        if 3 <= slash_cnt:
                            new_r.append((PToken.CHAR, elt[1][:ii+1]))
                            new_r.append((PToken.DOLLAR,))
                            return tuple(new_r)
            new_r.append(elt)
        else:
            return tuple(new_r)
    elif ty == PToken.GROUP:
        return tuple(remove_path(elt) if ii > 1 else elt
                     for ii, elt in enumerate(r))
    else:
        return r


def classify_char(ch):
    for k,v in charsets.items():
        if ch in v:
            return k
    else:
        return CharSet.OTHER



def convert_bars(r: Tuple, cutoff: int = 10) -> Tuple:
    """Reduce number of CHARs in a BAR expression to the cutoff number."""

    ty = r[0]

    if ty == BAR:
        tail_converted = tuple(map(convert_bars, r[1:]))

        grouped = toolz.groupby(lambda x: classify_char(x[1]) if x[0] == PToken.CHAR else CharSet.OTHER,
                                tail_converted)

        if CharSet.WORD in grouped and cutoff < len(grouped[CharSet.WORD]):
            logger.info('reducing WORD choices')
            grouped[CharSet.WORD] = toolz.take(cutoff, grouped[CharSet.WORD])

        return (PToken.BAR,) + tuple(toolz.concat(grouped.values()))
    elif ty == PToken.BACKREF:
        raise NotImplementedError
    elif ty == PToken.CHAR:
        return r
    elif ty == PToken.GROUP:
        return tuple(convert_bars(elt) if ii > 1 else elt
                     for ii, elt in enumerate(r))
    else:
        return tuple(convert_bars(elt) if ii > 0 else elt
                     for ii, elt in enumerate(r))


def symbolic_collections(xs: Sequence[str]):

    def _sort(xx):
        out = ''
        for cc in xx:
            in_domain_like_block = (out and out[-1] == 'a')
            if cc == '.' or cc == '/':
                out += cc
            elif not in_domain_like_block:
                out += 'a'
        return out

    return toolz.groupby(_sort, xs)


def _make_encoded_symbol(signature, nn: int) -> bytes:
    return SYMBOL_START + hex(nn)[2:].encode('utf8') + SYMBOL_END


def convert_to_encoded_symbols(r: Tuple, mapping: Dict[int, Tuple[str]]) -> Tuple[Tuple, Dict[int, Tuple[str]]]:
    """Convert unions (BARs) of character strings to encoded symbols.

    The symbols are encoded character strings that are illegal in URLs.  Outputs a tuple of
    processed AST, plus a dictionary mapping the encoded symbols to the concrete values they can
    take on.

    Each symbol only represents a single type of string. The types are:

    - strings that contain no metachars
    - strings that contain literal dots
    - strings that contain a slash

    :param mapping: Mapping of encoded symbols. Mapping gets mutated.

    """

    ty = r[0]

    if ty == BAR and all(elt[0] == PToken.CHAR for elt in r[1:]):
        num_orig_keys = len(mapping)
        extension = {}
        literals = []
        encoded = {}
        for sig, cc in symbolic_collections(elt[1] for elt in r[1:]).items():
            if len(cc) > 1 and sig == 'a':
                # Only convert signatures that have no domain separator metachars.
                # Otherwise, fallback to default behavior.
                k = num_orig_keys + len(extension)
                encoded[k]: bytes = _make_encoded_symbol(sig, k)
                extension[k] = cc
            else:
                literals.append(cc[0])
        new_vals = tuple((PToken.CHAR, vv) for vv in toolz.concatv(encoded.values(), literals))
        new_mapping = toolz.merge(mapping, extension)
        if len(new_vals) == 1:
            return (new_vals[0], new_mapping)
        else:
            return ((PToken.BAR,) + new_vals, new_mapping)
    elif ty == PToken.BACKREF:
        raise NotImplementedError
    elif ty == PToken.CHAR:
        return (r, mapping)
    else:
        start_idx = 2 if ty == PToken.GROUP else 1
        elts = []
        for idx, elt in enumerate(r):
            if idx >= start_idx:
                converted, mapping = convert_to_encoded_symbols(elt, mapping)
                elts.append(converted)
            else:
                elts.append(elt)

        return (elts, mapping)


def convert_stars(r: Tuple, star_lengths: Iterable[int]) -> Tuple:
    """Replace STAR expressions with finite BAR expressions"""
    ty = r[0]

    if ty == STAR:
        expanded = tuple((CONCAT,) + tuple([convert_stars(r[1], star_lengths)] * ll)
                         for ll in star_lengths if ll > 0)
        ans = (BAR, (EMPTY,)) + expanded
        return ans
    elif ty == BACKREF:
        raise NotImplementedError
    elif ty == CHAR:
        return r
    elif ty == GROUP:
        return tuple(convert_stars(elt, star_lengths) if ii > 1 else elt
                     for ii, elt in enumerate(r))
    else:
        return tuple(convert_stars(elt, star_lengths) if ii > 0 else elt
                     for ii, elt in enumerate(r))

def convert_chars(r):
    ty = r[0]

    if ty == CHAR:
        if 'http' in r[1]:
            return r
        elif 0 < len(r[1]):
            return (CHAR, r[1][0] + '_')
        else:
            return (CHAR, r[1])
    elif ty == BACKREF:
        raise NotImplementedError
    elif ty == GROUP:
        return tuple(convert_chars(elt) if ii > 1 else elt
                     for ii, elt in enumerate(r))
    else:
        return tuple(convert_chars(elt) if ii > 0 else elt
                     for ii, elt in enumerate(r))


def combine_chars(r):
    ty = r[0]

    if ty == CONCAT:
        tail = list(r[1:])

        marker = 0
        while marker < len(tail):
            if marker + 1 < len(tail) and tail[marker][0] == CHAR and tail[marker+1][0] == CHAR:
                tail[marker:marker+2] = [(CHAR, tail[marker][1] + tail[marker+1][1])]
            else:
                if tail[marker][0] != CHAR:
                    tail[marker] = combine_chars(tail[marker])

                marker += 1

        if len(tail) == 1:
            return tail[0]
        else:
            return (CONCAT,) + tuple(tail)
    elif ty == BACKREF:
        raise NotImplementedError
    elif ty == CHAR:
        return r
    elif ty == GROUP:
        return tuple(combine_chars(elt) if ii > 1 else elt
                     for ii, elt in enumerate(r))
    else:
        return tuple(combine_chars(elt) if ii > 0 else elt
                     for ii, elt in enumerate(r))



def combine_on_token(r: Tuple, target_token: PToken) -> Tuple:
    """Flatten nested CONCAT or BAR expressions"""
    assert target_token in (CONCAT, BAR)

    ty = r[0]

    if isinstance(r[0], str):
        return r[0]
    elif ty == target_token:
        def tail_if_match(x):
            if x[0] == target_token:
                return list(x[1:])
            else:
                return [x]

        tail = tuple(toolz.concat(tail_if_match(combine_on_token(elt, target_token)) for elt in r[1:]))

        if len(tail) == 1:
            return tail[0]
        else:
            return (target_token,) + tail
    elif ty == BACKREF:
        raise NotImplementedError
    elif ty == CHAR:
        return r
    elif ty == GROUP:
        return tuple(combine_on_token(elt, target_token) if ii > 1 else elt
                        for ii, elt in enumerate(r))
    else:
        return tuple(combine_on_token(elt, target_token) if ii > 0 else elt
                     for ii, elt in enumerate(r))


def flatten_regex(r: Tuple) -> Tuple:
    r2 = combine_on_token(r, CONCAT)
    r3 = combine_on_token(r2, BAR)
    r4 = combine_chars(r3)
    return r4
