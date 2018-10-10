from pytest import raises

import hack_url_re.parsing
from hack_url_re.parsing import PToken
from hack_url_re.preprocessing import combine_on_token

parse = hack_url_re.parsing.RegexParser().parse


def test_backslash():
    ex = r"\:"
    parsed = parse(ex)
    assert parsed['root'] == parse(r':')['root'] == (PToken.CHAR, ':')

    del ex, parsed

    ex = r"\^"
    parsed = parse(ex)
    assert parsed['root'] == (PToken.CHAR, '^')

    del ex, parsed

    with raises(NotImplementedError):
        ex = r"\p"
        parsed = parse(ex)
        del ex, parsed


    ex = r'\@\:\/x\\/\/x\.\?P\=V.+'
    ex2 = r'@:/x\\//x\.\?P=V.+'
    assert parse(ex)['root'] == parse(ex2)['root']


def test_negated_dot():
    r1 = parse(r"[^\.]")['root']

    r2 = combine_on_token(r1, PToken.BAR)

    chars = set(elt[1] for elt in r2[1:])

    assert '.' not in chars
    assert set('/abcdefg01234') <= chars


def test_negated_caret():
    r1 = parse(r"[^^]")['root']

    r2 = combine_on_token(r1, PToken.BAR)

    chars = set(elt[1] for elt in r2[1:])

    assert '^' not in chars
    assert set('/abcdefg01234') <= chars
