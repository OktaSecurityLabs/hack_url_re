from typing import Callable, Tuple, Any, Dict
from functools import partial

import z3

from hack_url_re.solving import (
    wildcard_trace, combination_wildcard_and_find_n, solver_frame, add_regex_constraints,
    OUTPUT_WILDCARD_MARKER,
)


solver = z3.Solver()

ResultAndReport = Tuple[z3.CheckSatResult, Any]

def solve_with_strategy(solver, regex: str,
                        strategy: Callable[[z3.Solver, Dict], ResultAndReport],
                        symbolic=False) -> ResultAndReport:
    symbols = add_regex_constraints(solver, regex, symbolic=symbolic)
    return strategy(solver, symbols)


def test_dot():
    with solver_frame(solver):
        regex = r"^http://(m.)?example\.com(?:$|/)"
        result, witness = solve_with_strategy(solver, regex, wildcard_trace)
        assert result == z3.sat

        assert witness['witness'] == 'http://m' + OUTPUT_WILDCARD_MARKER + 'example.com'


def test_optional_dollar():
    with solver_frame(solver):
        ss = r"^https://example\.com(xyz.$|/abc)"
        result, witness = solve_with_strategy(solver, ss, wildcard_trace)
        assert result == z3.sat

        # TODO: do a lower level test, use z3 to prove the witness is always the same
        assert witness['witness'] == 'https://example.comxyz☠'
        del result, witness


def test_vulnerable_prefix():
    with solver_frame(solver):
        ss = r".*https://example\.com($|/)"
        result, witness = solve_with_strategy(solver, ss, wildcard_trace)
        assert result == z3.sat

        # proto separator could be in the .* or be the // after https
        assert (witness['witness'] == OUTPUT_WILDCARD_MARKER * 4 + 'https://example.com'
                or witness['witness'] == OUTPUT_WILDCARD_MARKER * 4 + 'https:')
        del result, witness


def test_vulnerable_prefix_2():
    with solver_frame(solver):
        ss = r".*a\.b\.com($|/)"
        result, witness = solve_with_strategy(solver, ss, wildcard_trace)
        assert result == z3.sat

        assert witness['witness'] == OUTPUT_WILDCARD_MARKER * 4 + 'a.b.com'
        del result, witness


def test_example_negated_dot():
    with solver_frame(solver):
        example16 = r"^https://[^\.]*\.example\.com(?:$|/)"
        result, witness = solve_with_strategy(solver, example16, combination_wildcard_and_find_n)
        assert result == z3.sat
        del result, witness

    with solver_frame(solver):
        example16a = r"^https://[^\.]\.example\.com"
        result, witness = solve_with_strategy(solver, example16a, combination_wildcard_and_find_n)
        assert result == z3.unsat
        del result, witness


def test_find_n():
    # the dot at the end is to test ignoring dots
    with solver_frame(solver):
        regex =  r'^https://x\.y\.com\d/\w+/x.x'
        max_finds = 10
        result, report = solve_with_strategy(
            solver, regex, partial(combination_wildcard_and_find_n, max_finds=max_finds))
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_witness = {'y.com{}'.format(ii) for ii in range(max_finds)}
        assert set(report['witness']) == expected_witness

        del result, report


def test_find_n_cc_tld():
    with solver_frame(solver):
        regex =  r'^https://\d\.y\.uk/\w+/x.x'
        max_finds = 10
        result, report = solve_with_strategy(
            solver, regex, partial(combination_wildcard_and_find_n, max_finds=max_finds))
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_witness = {'{}.y.uk'.format(ii) for ii in range(max_finds)}
        assert set(report['witness']) == expected_witness

        del result, report


def test_find_n_cc_tld_mixed():
    with solver_frame(solver):
        regex =  r'^https://([012345678]\.y|z)\.uk/\w+/x.x'
        max_finds = 10
        result, report = solve_with_strategy(
            solver, regex, partial(combination_wildcard_and_find_n, max_finds=max_finds))
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_3ld_witness = {'{}.y.uk'.format(ii) for ii in range(max_finds)}
        assert len(set(report['witness']).intersection(expected_3ld_witness)) == len(expected_3ld_witness) - 1

        del result, report


def test_dot_symbolic():
    with solver_frame(solver):
        regex = r"^http://(m.)?example\.com(?:$|/)"
        result, witness = solve_with_strategy(solver, regex, wildcard_trace, symbolic=True)
        assert result == z3.sat

        assert witness['witness'] == 'http://m' + OUTPUT_WILDCARD_MARKER + 'example.com'


def test_find_n_symbolic():
    with solver_frame(solver):
        regex =  r'^https://(aaaaaa|bbbbbb|cccccc|dddddd|eeeeee)(ffffff|gggggg)\.com/'
        max_finds = 10
        result, report = solve_with_strategy(
            solver, regex, partial(combination_wildcard_and_find_n, max_finds=max_finds), symbolic=True)
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_witness = {'{}{}.com'.format(c1*6, c2*6) for c1 in 'abcde' for c2 in 'fg'}
        assert set(report['witness']) == expected_witness

        del result, report
