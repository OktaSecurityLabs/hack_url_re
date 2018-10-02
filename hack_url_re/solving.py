import contextlib
import logging
from typing import Iterable, List, Tuple, Dict

import z3
import toolz as tz

from .compiling import RegexStringExpr
from .constants import cc_tlds
from .abstracting import concretizations

DEBUG = False
logger = logging.getLogger(__name__)


@contextlib.contextmanager
def solver_frame(solver):
    solver.push()
    try:
        yield solver
    finally:
        solver.pop()


def check_formulae(solver, *formulae):
    with solver_frame(solver):
        solver.add(*formulae)
        result = solver.check()
        if result == z3.sat:
            return (z3.sat, solver.model())
        else:
            return (result, None)


is_https = z3.Bool('is_https')
is_http = z3.Bool('is_http')
proto = z3.String('proto')
proto_delimiter = z3.String('proto_delimiter')
domain = z3.String('domain')
fqdn = z3.String('fqdn')
root_domain = z3.String('root_domain')
base_url = proto + '://' + fqdn
unknown_string = z3.String('solution')


z3_byte_to_ord = {z3.StringVal(bytes([ii])): ii for ii in range(256)}

def z3_str_to_bytes(zs: z3.StringVal):
    ll = z3.simplify(z3.Length(zs)).as_long()
    return bytes([z3_byte_to_ord[z3.simplify(zs[ii])] for ii in range(ll)])

def z3_str_to_str(zs: z3.StringVal):
    return str(z3_str_to_bytes(zs), encoding='utf8')

def public_vars(model):
    return {k:model[k] for k in model.decls()
            if not k.name().startswith('_')}


WILDCARD_MARKER = '<'
OUTPUT_WILDCARD_MARKER = '☠'  # skull emoji

def add_regex_constraints(solver, regex, max_length=None, symbolic=False) -> Dict[int, List[str]]:
    if max_length is None:
        # TODO: get max length from parsed regex.
        max_length = len(regex) + 15

    # WILDCARD_MARKER is not a valid URL char. Note that wildcards match ':' and '/'
    rs = RegexStringExpr(regex, unknown_string, dot_charset=WILDCARD_MARKER, symbolic=symbolic)
    expr = rs.re_expr()
    solver.add(expr)

    solver.add(z3.Length(unknown_string) <= max_length)
    return rs.symbols


def wildcard_trace(solver, symbols: Dict[int, List[str]], use_priming=True) -> Tuple[z3.CheckSatResult, Dict]:
    """Return the result of the attack (sat means attack was successful) and associated data.

    If the attack was successful, associated data includes what attack was executed, witness
    information, and the solution found.  The dictionary keys are "strategy", "solution", "witness".

    Otherwise, associated data includes the attack that was executed, plus debug info under the key
    "debug_info".

    """

    if use_priming:
        # prime the solver with an easy question.
        # In `test_optional_dollar` it seems to give several folds speedup, if you used the same
        # solver for `test_dot` previously.
        prime_result, prime_model = check_formulae(solver, z3.Not(RegexStringExpr.ignore_wildcards))
        logger.info('check %s', prime_result)
        if prime_result == z3.sat:
            logger.debug(public_vars(prime_model))
        else:
            solver.reset()
            return prime_result, None

    base = proto + proto_delimiter + fqdn

    solver.add(
        z3.Or(proto_delimiter == z3.StringVal('//'), proto_delimiter == z3.StringVal(WILDCARD_MARKER * 2)),
        z3.Xor(z3.PrefixOf(base + '/', unknown_string), base == unknown_string),
        z3.Not(z3.Contains(proto, '/')),
        z3.Not(z3.Contains(fqdn, '/')),
        z3.Length(proto) > 0,
        z3.Length(fqdn) > 0,
        )

    if DEBUG:
        #debug_result, debug_model = check_formulae(solver, unknown_string == debug_model[unknown_string])
        #logger.debug(debug_model)

        debug_result = solver.check()
        logger.debug(debug_result)
        if debug_result == z3.sat:
            debug_model = solver.model()
            logger.debug(public_vars(debug_model))
            ans = z3.simplify(debug_model[proto] + debug_model[proto_delimiter] + debug_model[fqdn])
        else:
            return debug_result, None


        #debug_result, debug_model = check_formulae(solver, (base_url != ans))

    result, model = check_formulae(solver,
                                   z3.Not(RegexStringExpr.ignore_wildcards),
                                   z3.Contains(proto + fqdn, z3.StringVal(WILDCARD_MARKER)))

    if result == z3.sat:
        _conc1 = lambda zs: tz.first(concretizations(z3_str_to_bytes(zs), symbols))
        logger.info(public_vars(model))
        ans = z3.simplify(model[proto] + model[proto_delimiter] + model[fqdn])
        return result, {
            'solution': _conc1(model[unknown_string]).replace(WILDCARD_MARKER, OUTPUT_WILDCARD_MARKER),
            'strategy': 'wildcard_trace',
            'witness': _conc1(ans).replace(WILDCARD_MARKER, OUTPUT_WILDCARD_MARKER)}
    else:
        return result, {'strategy': 'wildcard_trace',
                        'debug_info': None}


def find_n_root_domains_ignoring_wildcards(solver: z3.Solver, symbols: Dict[int, List[str]],
                                           require_literal_dot_in_domain: bool,
                                           levels: int, max_finds: int):
    """If enough root domains are found, report vulnerability.

    :param levels: number of levels of domains to consider as part of the root domain. Either 2 or 3.
        If 3, the TLD needs to be a Country Code.
    :param max_finds: threshold number of root domains to find before considering as vulnerability.
    :return: tuple of sat result, witness or debug info
    """

    Not = z3.Not
    And = z3.And
    Or = z3.Or
    Xor = z3.Xor
    Contains = z3.Contains
    String = z3.String
    StringVal = z3.StringVal
    Length = z3.Length
    Implies = z3.Implies
    PrefixOf = z3.PrefixOf
    SuffixOf = z3.SuffixOf
    Concat = z3.Concat

    tld = String('tld')
    sld = String('sld')
    third_ld = String('3ld')
    DNS_root = String('DNS_root')
    dot_in_domain = Contains(root_domain, '.')

    domain_expr = z3.simplify(And(
        Or(DNS_root == StringVal('.'), DNS_root == StringVal('')),

        Xor(Concat(root_domain, DNS_root) == fqdn,
            And(SuffixOf(Concat(StringVal('.'), root_domain, DNS_root), fqdn),
                dot_in_domain)),

        Implies(dot_in_domain,
                And(Not(Contains(tld, '.')),
                    Not(Contains(sld, '.')),
                    Length(tld) > 0,
                    root_domain == (Concat(sld, StringVal('.'), tld)
                                    if levels < 3
                                    else Concat(third_ld, StringVal('.'), sld, StringVal('.'), tld)))),

        Implies(Not(dot_in_domain), And(Concat(root_domain, DNS_root) == fqdn,
                                        tld == StringVal(''),
                                        sld == StringVal(''),)),
    ))


    with solver_frame(solver):
        solver.add(domain_expr)
        solver.add(RegexStringExpr.ignore_wildcards)
        if require_literal_dot_in_domain or levels >= 3:
            solver.add(dot_in_domain)

        if levels >= 3:
            solver.add(z3.simplify(And(
                Not(Contains(third_ld, '.')),
                Length(sld) > 0,
                Length(third_ld) > 0,
                Or(*(tld == StringVal(ss) for ss in cc_tlds)),
            )))

        results = []
        found = set()
        found_root_domains = set()
        result = z3.sat

        logger.info('searching for n root_domains')

        _concs = lambda zs: concretizations(z3_str_to_bytes(zs), symbols)
        solution = None

        while len(found_root_domains) < max_finds and result == z3.sat:
            result = solver.check()
            results.append(result)
            if result == z3.sat:
                model = solver.model()
                _root_domain = model[root_domain]
                parts = (model[proto], model[proto_delimiter], model[fqdn])
                assert all(part is not None for part in parts)
                logger.info(public_vars(model))
                found.update(_concs(z3.simplify(z3.Concat(*parts))))
                found_root_domains.update(_concs(_root_domain))
                solver.add(root_domain != _root_domain)
                solution = tz.first(_concs(model[unknown_string]))

        # if not sat, return the would-be witness for debugging
        if result == z3.sat:
            root_domains_label = 'witness'
        else:
            root_domains_label = 'root_domains'

        return result, {'strategy': 'find_n_root_domains_ignoring_wildcards',
                        'found': list(found),
                        root_domains_label: list(found_root_domains),
                        'levels': levels,
                        'solution': solution}

def combine_sat_results(r1, r2):
    if r1 == z3.sat or r2 == z3.sat:
        return z3.sat
    elif r1 == z3.unsat and r2 == z3.unsat:
        return z3.unsat
    else:
        return z3.unknown

def combination_wildcard_and_find_n(solver,
                                    symbols: Dict[int, List[str]],
                                    require_literal_dot_in_domain=False,
                                    max_finds=10):

    result1, report1 = wildcard_trace(solver, symbols)
    logger.info('wildcard_trace results: %s %s', result1, report1)
    if result1 == z3.sat:
        return result1, report1

    else:
        # Note find_n_root_domains_ignoring_wildcards requires some definitions from wildcard_trace
        # and cannot be run independently.
        result2, report2 = find_n_root_domains_ignoring_wildcards(solver,
                                                                  symbols,
                                                                  require_literal_dot_in_domain,
                                                                  levels=2,
                                                                  max_finds=max_finds)

        combined_result_2 = combine_sat_results(result1, result2)

        # Finish if attack was found, or none of the possible 2-level domains has a CC TLD.
        if (combined_result_2 == z3.sat or not any(found.endswith('.' + cc_tld)
                                        for found in report2['root_domains']
                                        for cc_tld in cc_tlds)):
            return combined_result_2, report2
        else:

            result3, report3 = find_n_root_domains_ignoring_wildcards(solver,
                                                                      symbols,
                                                                      require_literal_dot_in_domain,
                                                                      levels=3,
                                                                      max_finds=max_finds)

            combined_result_3 = combine_sat_results(combined_result_2, result3)

            if combined_result_3 == z3.sat:
                return combined_result_3, report3
            else:
                _3lds = report3['root_domains']
                _2lds = [_2ld for _2ld in report2['root_domains']
                         if not any(_3ld.endswith('.' + _2ld) for _3ld in _3lds)]

                found_root_domains_3 = _3lds + _2lds

                return (z3.sat if len(found_root_domains_3) >= max_finds else combined_result_3,
                        {'solution': report3['solution'],
                         'strategy': report3['strategy'],
                         'found': report2['found'] + [elt for elt in report3['found']
                                                      if elt not in report2['found']],
                         'witness': found_root_domains_3})


def get_warnings(regex):
    warnings = []

    if not regex.startswith('^'):
        warnings.append("Regex doesn't begin with `^`")

    return warnings
