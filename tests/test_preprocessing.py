import string
from typing import Tuple

from hack_url_re.parsing import (PToken, RegexParser,
                                      EMPTY, CHAR, DOT, STAR, BAR, CONCAT, GROUP, BACKREF, CARET, DOLLAR)

from hack_url_re.preprocessing import combine_on_token, convert_bars, combine_chars, flatten_regex


def parse(ex):
    parser = RegexParser()
    return parser.parse(ex)['root']


def convert_bars_to_sets(tree: Tuple):
    recur = convert_bars_to_sets
    if tree[0] == BAR:
        return (BAR, frozenset(recur(tree[1:])))
    else:
        return tuple(recur(elt) if isinstance(elt, Tuple) else elt
                     for elt in tree)


def test_convert_bars_1():
    ex = (BAR, (CHAR, 'a'), (CHAR, 'b'), (CHAR, 'c'), (CHAR, 'd'), (CHAR, 'e'), (CHAR, 'f'), (CHAR, 'g'))

    initial = set(ex[1:])

    cutoff= 5

    converted = convert_bars(ex, cutoff=cutoff)

    final = set(converted[1:])

    assert final <= initial
    assert len(final) == cutoff


def test_combine_chars():
    ex = parse(string.ascii_lowercase)

    combined = combine_chars(combine_on_token(ex, PToken.CONCAT))

    assert len(combined) == 2
    assert combined[0] == PToken.CHAR
    assert combined[1] == string.ascii_lowercase


def test_singletons():
    ex = combine_on_token((PToken.CONCAT, (PToken.CHAR, 'a')), PToken.CONCAT)
    assert ex == (PToken.CHAR, 'a')

    ex2 = combine_on_token((PToken.BAR, (PToken.CHAR, 'a')), PToken.BAR)
    assert ex2 == (PToken.CHAR, 'a')


def test_flatten_regex():
    ex = flatten_regex(parse(r'^abc(lmn[abc]|aaa)'))

    expected = (CONCAT,
                (CARET,), (CHAR, 'abc'), (GROUP, 1, (BAR,
                                                     (CONCAT,
                                                      (CHAR, 'lmn'),
                                                      (BAR, (CHAR, 'a'), (CHAR, 'b'), (CHAR, 'c'))),
                                                     (CHAR, 'aaa'))))

    assert convert_bars_to_sets(ex) == convert_bars_to_sets(expected)
