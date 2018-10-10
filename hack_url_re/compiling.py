import z3

from pdb import set_trace

import string
import toolz
import enum
import logging
from typing import Iterable, Tuple, Set

from . import parsing
from .parsing import (PToken, EMPTY, CHAR, DOT, STAR, BAR, CONCAT, GROUP, BACKREF, CARET, DOLLAR)
from .preprocessing import (convert_stars, convert_bars, flatten_regex, remove_path)


logger = logging.getLogger(__name__)

# set of nonzero lengths with which to approximate star
# the zero length is included automatically
DEFAULT_STAR_LENGTHS = [4]

# space is not valid URL char.
# pound (#) is invalid in domain. It gets replaced with /# in Chrome in the URL bar.
# question (?) is also invalid in domain, and gets replaced with /? in Chrome URL bar.
DEFAULT_DOT_CHARSET = 'abcdefghijklmnop012345' + "/"


class RegexStringExpr:
    scratch_var_cnt = 0
    ignore_wildcards = z3.Bool('ignore_wildcards')

    def _gen_string_var(self):
        x =  z3.String('_x_{}'.format(self.string_var_count))
        self.string_var_count += 1
        return x

    def _gen_bool_var(self):
        b =  z3.Bool('_b_{}'.format(self.bool_var_count))
        self.bool_var_count += 1
        return b

    def __init__(self, regex: str, unknown: z3.StringSort(),
                 word_choice_cutoff=10,
                 dot_charset=DEFAULT_DOT_CHARSET,
                 star_lengths: Iterable[int] = DEFAULT_STAR_LENGTHS):
        """
        Compiles Regex to Z3 String expressions

        :param dot_charset: Characters that the DOT metachar can match. This should be limited to
            valid URL characters, or can be set to a taint marker.

        """

        self.unknown = unknown
        self.star_lengths = star_lengths

        self.string_var_count = 0
        self.bool_var_count = 0

        _parser = parsing.RegexParser()
        parse_result = _parser.parse(regex)
        self.parsing_errors = parse_result['errors']
        regex_0 = flatten_regex(parse_result['root'])
        regex_1 = remove_path(regex_0)
        regex_2 = convert_stars(regex_1, star_lengths)
        regex_3 = convert_bars(regex_2, cutoff=word_choice_cutoff)
        self.regex = regex_3
        assert self.regex
        self.groups = parse_result['groups']
        self.backrefs = parse_result['backrefs']
        self.dot_charset = dot_charset

    def _sat_expr(self, regex: Tuple) -> Tuple[z3.SeqRef, z3.BoolRef, z3.BoolRef, z3.BoolRef]:
        """

        :returns: string that matches regex, constraint on string,
             whether string contains caret, whether string contains dollar

        Whether there is a caret or dollar needs to be tracked because they imply constraints on
        neighboring strings to the one returned.

        """

        ty = regex[0]

        if ty == EMPTY:
            return (z3.StringVal(''), z3.BoolVal(True), z3.BoolVal(False), z3.BoolVal(False))

        elif ty == CHAR:
            return (z3.StringVal(regex[1]), z3.BoolVal(True), z3.BoolVal(False), z3.BoolVal(False))

        elif ty == DOT:
            x = self._gen_string_var()
            constraint = z3.And(z3.Implies(self.ignore_wildcards, x == z3.StringVal('')),
                                z3.Implies(z3.Not(self.ignore_wildcards),
                                           z3.Or(*(x == z3.StringVal(y) for y in self.dot_charset))))
            return (x, constraint, z3.BoolVal(False), z3.BoolVal(False))

        elif ty == STAR:
            # STAR should have been approximated with something else during preprocessing.
            raise NotImplementedError

        elif ty == BAR:
            ys, constraints_list, carets_list, dollars_list = zip(*map(self._sat_expr, regex[1:]))

            x = self._gen_string_var()
            x_constraint = z3.Or(*(z3.And(x == y, y_constraint)
                                   for y, y_constraint in zip(ys, constraints_list)))

            return (x, x_constraint, z3.Or(*carets_list), z3.Or(*dollars_list))
        elif ty == CONCAT:

            ys, y_constraints, carets_list, dollars_list = zip(*map(self._sat_expr, regex[1:]))

            x = z3.Concat(*ys)

            start_constraints = (
                z3.Implies(b, z3.Length(y) == 0)
                for ii, b in enumerate(carets_list)
                for y in ys[:ii])

            end_constraints = (
                z3.Implies(b, z3.Length(y) == 0)
                for ii, b in enumerate(dollars_list)
                for y in ys[ii+1:]
                )

            x_constraint = z3.And(*toolz.concatv(y_constraints, start_constraints, end_constraints))

            return (x, x_constraint, z3.Or(*carets_list), z3.Or(*dollars_list))

        elif ty == GROUP:
            # backrefs not supported
            idx = regex[1] - 1   # not used currently; would be used to implement backrefs
            inner = regex[2]
            return self._sat_expr(inner)

        elif ty == BACKREF:
            raise NotImplementedError

        elif ty == CARET:
            assert len(regex) == 1
            b = self._gen_bool_var()
            return (z3.StringVal(''), b, b, z3.BoolVal(False))

        elif ty == DOLLAR:
            assert len(regex) == 1
            b = self._gen_bool_var()
            return (z3.StringVal(''), b, z3.BoolVal(False), b)

        else:
            raise ValueError("Unknown regex_parser type '%s'" % repr(ty))

    def re_expr(self):
        ss, expr, carets, dollars = self._sat_expr(self.regex)
        return z3.simplify(z3.And(self.unknown == ss, expr))
