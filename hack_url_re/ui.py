import argparse
import json
import logging
from enum import Enum
from sys import stdin, stdout

import z3

from . import solving, compiling


class RegexSemantics(Enum):
    search = 0   # python re.search
    match = 1    # python re.match


def serialize_keys(dd: dict):
    '''Visit each key in a dict of dicts, and serialize the keys.'''
    out = {}

    for k,v in dd.items():
        k2 = k if isinstance(k, str) else k.name

        if isinstance(v, dict):
            v2 = serialize_keys(v)
        else:
            v2 = v

        out[k2] = v2

    return out


def set_verbose():
    solving.logger.setLevel(logging.INFO)
    compiling.logger.setLevel(logging.INFO)

    
def solve(regex, quick, require_literal_dot_in_domain, semantics=RegexSemantics.search):
    solver = z3.Solver()

    if semantics == RegexSemantics.search:
        regex = r'.*' + regex + r'.*'

    with solving.solver_frame(solver):
        solving.add_regex_constraints(solver, regex)
        if quick:
            result, evidence = solving.wildcard_trace(solver)
        else:
            result, evidence = solving.combination_wildcard_and_find_n(
                solver,
                require_literal_dot_in_domain=require_literal_dot_in_domain
            )

    return result, evidence
            

def main():
    parser = argparse.ArgumentParser(
        description="Reads a regex from stdin and attempts to hack it. Output is a json report.")
    parser.add_argument('--strip-newline', '-n', action='store_true', help=
                        '''Removes newlines from the end of the regex.''')

    parser.add_argument('--quick', '-q', action='store_true',
                        help='''Applies a quick attack.  Otherwise applies a comprehensive attack,
                        which will find everything that the quick attack does.''')

    parser.add_argument('--ensure-ascii', action='store_true',
                        help='''Ensure ASCII output.''')

    parser.add_argument('--require-literal-dot-in-domain', action='store_true',
                        help='''Require at least one dot in the domain name.''')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='''Enable verbose logging.''')


    args = parser.parse_args()

    regex = stdin.read()

    if args.strip_newline:
        regex = regex.rstrip('\n')

    if args.verbose:
        set_verbose()

    result, evidence = solve(regex, quick=args.quick, require_literal_dot_in_domain=args.require_literal_dot_in_domain)

    #stdout.write(json.dumps(regex))
    out = {'result': str(result)}
    out.update(serialize_keys(evidence))

    stdout.write(json.dumps(out, indent=4, separators=(',', ': '), ensure_ascii=args.ensure_ascii))
    stdout.write('\n')
    stdout.flush()

