import z3

from hack_url_re.solving import (
    wildcard_trace, combination_wildcard_and_find_n, solver_frame, add_regex_constraints,
    OUTPUT_WILDCARD_MARKER,
)


solver = z3.Solver()


def test_dot():
    with solver_frame(solver):
        regex = r"^http://(m.)?example\.com(?:$|/)"
        add_regex_constraints(solver, regex)
        result, witness = wildcard_trace(solver)
        assert result == z3.sat

        assert witness['witness'] == 'http://m' + OUTPUT_WILDCARD_MARKER + 'example.com'


def test_optional_dollar():
    with solver_frame(solver):
        ss = r"^https://example\.com(xyz.$|/abc)"
        add_regex_constraints(solver, ss)
        result, witness = wildcard_trace(solver, ss)
        assert result == z3.sat

        # TODO: do a lower level test, use z3 to prove the witness is always the same
        assert witness['witness'] == 'https://example.comxyz☠'
        del result, witness


def test_vulnerable_prefix():
    with solver_frame(solver):
        ss = r".*https://example\.com($|/)"
        add_regex_constraints(solver, ss)
        result, witness = wildcard_trace(solver)
        assert result == z3.sat

        # proto separator could be in the .* or be the // after https
        assert (witness['witness'] == OUTPUT_WILDCARD_MARKER * 4 + 'https://example.com'
                or witness['witness'] == OUTPUT_WILDCARD_MARKER * 4 + 'https:')
        del result, witness


def test_vulnerable_prefix_2():
    with solver_frame(solver):
        ss = r".*a\.b\.com($|/)"
        add_regex_constraints(solver, ss)
        result, witness = wildcard_trace(solver)
        assert result == z3.sat

        assert witness['witness'] == OUTPUT_WILDCARD_MARKER * 4 + 'a.b.com'
        del result, witness


def test_example_negated_dot():
    with solver_frame(solver):
        example16 = r"^https://[^\.]*\.example\.com(?:$|/)"
        add_regex_constraints(solver, example16)
        result, witness = combination_wildcard_and_find_n(solver)
        assert result == z3.sat
        del result, witness

    with solver_frame(solver):
        example16a = r"^https://[^\.]\.example\.com"
        add_regex_constraints(solver, example16a)
        result, witness = combination_wildcard_and_find_n(solver)
        assert result == z3.unsat
        del result, witness


def test_find_n():
    # the dot at the end is to test ignoring dots
    with solver_frame(solver):
        regex =  r'^https://x\.y\.com\d/\w+/x.x'
        max_finds = 10
        add_regex_constraints(solver, regex)
        result, report = combination_wildcard_and_find_n(solver, max_finds=max_finds)
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_witness = {'y.com{}'.format(ii) for ii in range(max_finds)}
        assert set(report['witness']) == expected_witness

        del result, report


def test_find_n_cc_tld():
    with solver_frame(solver):
        regex =  r'^https://\d\.y\.uk/\w+/x.x'
        max_finds = 10
        add_regex_constraints(solver, regex)
        result, report = combination_wildcard_and_find_n(solver, max_finds=max_finds)
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_witness = {'{}.y.uk'.format(ii) for ii in range(max_finds)}
        assert set(report['witness']) == expected_witness

        del result, report


def test_find_n_cc_tld_mixed():
    with solver_frame(solver):
        regex =  r'^https://([012345678]\.y|z)\.uk/\w+/x.x'
        max_finds = 10
        add_regex_constraints(solver, regex)
        result, report = combination_wildcard_and_find_n(solver, max_finds=max_finds)
        assert result == z3.sat
        assert len(report['witness']) == max_finds

        expected_3ld_witness = {'{}.y.uk'.format(ii) for ii in range(max_finds)}
        assert len(set(report['witness']).intersection(expected_3ld_witness)) == len(expected_3ld_witness) - 1

        del result, report
