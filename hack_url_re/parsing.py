import string
from functools import reduce

import ply.lex as lex
import ply.yacc as yacc

from enum import Enum

class PToken(Enum):
    [EMPTY, CHAR, DOT, STAR, BAR, CONCAT, GROUP, BACKREF, CARET, DOLLAR] = range(10)

    def __repr__(self):
        return self.name

[EMPTY, CHAR, DOT, STAR, BAR, CONCAT, GROUP, BACKREF, CARET, DOLLAR] = list(PToken)

# NOTE: missing pound ('#'), less than ('<'), greater than ('>'). These are not legal URL characters.
# Although pound can be used in the browser address bar, it's not technically part of the URL.
CHARSET = string.ascii_lowercase + string.ascii_uppercase + string.digits + " :/'!@%&=_" + ".*+?|()[]^-{},\\"

character_classes = {
    's' : " ",
    'd' : "0123456789",
    'w' : "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_", # javascript charset for \w
}

class RegexLexer:
    tokens = (
        "NON_META_CHAR", "DIGIT",
        "DOT", "STAR", "PLUS", "QUESTION",
        "BAR",
        "LPAREN", "RPAREN",
        "LBRACKET", "RBRACKET",
        "CARET", "DASH", "DOLLAR",
        "LBRACE", "RBRACE", "COMMA",
        "BACKSLASH",
        "COLON",
    )

    def t_NON_META_CHAR(self, t):
        r"[a-zA-Z /'!@#%&=_]"
        return t
    def t_DIGIT(self, t):
        r"[0-9]"
        return t
    t_DOT, t_STAR, t_PLUS, t_QUESTION = r"\.", r"\*", r"\+", r"\?"
    t_BAR = r"\|"
    t_LPAREN, t_RPAREN = r"\(", r"\)"
    t_LBRACKET, t_RBRACKET = r"\[", r"\]"
    t_CARET, t_DASH, t_DOLLAR = r"\^", r"-", r"\$"
    t_LBRACE, t_RBRACE, t_COMMA = r"\{", r"\}", r","
    t_BACKSLASH = r"\\"
    t_COLON = r"\:"

    def t_error(self, t):
        print ("Lexer error at '%s'" % t.value[0])

    def __init__(self):
        self.lexer = lex.lex(module=self)

class RegexParser:

    def p_regex_term(self, p):
        """regex : term"""
        p[0] = p[1]
    def p_regex_bar(self, p):
        """regex : BAR"""
        p[0] = (EMPTY,)
    def p_regex_term_bar(self, p):
        """regex : term BAR"""
        p[0] = (BAR, (EMPTY,), p[1])
    def p_regex_union(self, p):
        """regex : term BAR regex"""
        p[0] = (BAR, p[1], p[3])
    def p_regex_bar_regex(self, p):
        """regex : BAR regex"""
        p[0] = (BAR, (EMPTY,), p[2])

    def p_factor_just_caret(self, p):
        """factor : CARET"""
        p[0] = (CARET,)
    def p_factor_just_dollar(self, p):
        """factor : DOLLAR"""
        p[0] = (DOLLAR,)

    def p_term_factor(self, p):
        """term : factor"""
        p[0] = p[1]
    def p_term_concat(self, p):
        """term : factor term"""
        p[0] = (CONCAT, p[1], p[2])

    def p_factor_char(self, p):
        """
        factor : NON_META_CHAR
               | DIGIT
               | DASH
               | COMMA
               | COLON
        """
        p[0] = (CHAR, p[1])
    def p_factor_dot(self, p):
        """factor : DOT"""
        p[0] = (DOT,)
    def p_factor_star(self, p):
        """factor : factor STAR"""
        p[0] = (STAR, p[1])
    def p_factor_plus(self, p):
        """factor : factor PLUS"""
        p[0] = (CONCAT, p[1], (STAR, p[1]))
    def p_factor_question(self, p):
        """factor : factor QUESTION"""
        p[0] = (BAR, p[1], (EMPTY,))
    def p_factor_non_capturing_group(self, p):
        """factor : LPAREN QUESTION COLON regex RPAREN"""
        self.groups.append(p[4])
        p[0] = (GROUP, len(self.groups), p[4])
    def p_factor_group(self, p):
        """factor : LPAREN regex RPAREN"""
        self.groups.append(p[2])
        p[0] = (GROUP, len(self.groups), p[2])
    #def p_factor_option_group(self, p):
    #    """factor : LPAREN BAR regex RPAREN"""
    #    self.groups.append(p[2])
    #    p[0] = (GROUP, len(self.groups), (BAR, (EMPTY,), p[2]))
    #def p_factor_option_group(self, p):
    #    """factor : LPAREN regex BAR RPAREN"""
    #    self.groups.append(p[2])
    #    p[0] = (GROUP, len(self.groups), (BAR, (EMPTY,), p[2]))
    def p_factor_backref(self, p):
        """factor : BACKSLASH DIGIT"""
        p[0] = (BACKREF, int(p[2]))
        self.backrefs.add(int(p[2]))
    def p_factor_set(self, p):
        """factor : set"""
        chars = list(p[1])
        chars = map(lambda x: (CHAR, x), chars)
        p[0] = reduce(lambda x, y: (BAR, x, y), chars)
    def p_factor_escape(self, p):
        """
        factor : BACKSLASH DOT
               | BACKSLASH STAR
               | BACKSLASH PLUS
               | BACKSLASH QUESTION
               | BACKSLASH BAR
               | BACKSLASH LPAREN
               | BACKSLASH RPAREN
               | BACKSLASH LBRACKET
               | BACKSLASH RBRACKET
               | BACKSLASH CARET
               | BACKSLASH LBRACE
               | BACKSLASH RBRACE
               | BACKSLASH DASH
               | BACKSLASH COMMA
               | BACKSLASH BACKSLASH
        """
        p[0] = (CHAR, p[2])
    def p_factor_escape_fallback(self, p):
        """
        factor : BACKSLASH NON_META_CHAR
               | BACKSLASH COLON
        """
        if p[2] in character_classes:
            chars = map(lambda x: (CHAR, x), character_classes[p[2]])
            p[0] = reduce(lambda x, y: (BAR, x, y), chars)
        elif p[2] in 'b' + 'DWS' + 'vh' + 'icIC' + 'p':
            raise NotImplementedError(r"Unimplemented character class '\{}'".format(p[2]))
        elif p[2] in ",-/'!:=&@#":
            p[0] = (CHAR, p[2])
        else:
            raise SyntaxError("Unknown escape '%s'" % p[2])

    def p_factor_brace_1(self, p):
        """factor : factor LBRACE number RBRACE"""
        inner = p[1]
        times = int(p[3])
        p[0] = reduce(lambda x, y: (CONCAT, x, y), [inner for _ in range(times)])
    def p_factor_brace_2(self, p):
        """factor : factor LBRACE number COMMA RBRACE"""
        inner = p[1]
        times = int(p[3])
        prefix = reduce(lambda x, y: (CONCAT, x, y), [inner for _ in range(times)])
        p[0] = (CONCAT, prefix, (STAR, inner))
    def p_factor_brace_3(self, p):
        """factor : factor LBRACE number COMMA number RBRACE"""
        inner = p[1]
        times1 = int(p[3])
        times2 = int(p[5])
        cases = []
        for l in range(times1, times2+1):
            case = reduce(lambda x, y: (CONCAT, x, y), [inner for _ in range(l)])
            cases.append(case)
        p[0] = reduce(lambda x, y: (BAR, x, y), cases)

    def p_number_single(self, p):
        """number : DIGIT"""
        p[0] = p[1]
    def p_number_multiple(self, p):
        """number : DIGIT number"""
        p[0] = p[1] + p[2]

    def p_set_positive(self, p):
        """set : LBRACKET set_items RBRACKET"""
        p[0] = p[2]
    def p_set_negative(self, p):
        """set : LBRACKET CARET latter_set_items RBRACKET"""
        p[0] = set(set(CHARSET) - p[3])

    def p_set_items_single(self, p):
        """set_items : set_item"""
        p[0] = p[1]
    def p_set_items_multiple(self, p):
        """set_items : set_item latter_set_items"""
        p[0] = p[1].union(p[2])
    def p_set_item_char(self, p):
        """set_item : set_non_meta_char"""
        p[0] = set([p[1]])

    def p_latter_set_item_char(self, p):
        """latter_set_item : set_item"""
        assert isinstance(p[1], set)
        p[0] = p[1]

    def p_latter_set_item_caret_char(self, p):
        """latter_set_item : CARET"""
        p[0] = set([p[1]])

    def p_latter_set_items_single(self, p):
        """latter_set_items : latter_set_item"""
        assert isinstance(p[1], set)
        p[0] = p[1]
    def p_latter_set_items_multiple(self, p):
        """latter_set_items : latter_set_item latter_set_items"""
        assert isinstance(p[1], set)
        p[0] = p[1].union(p[2])

    def p_set_item_range(self, p):
        """set_item : set_non_meta_char DASH set_non_meta_char"""
        begin = ord(p[1])
        end = ord(p[3])
        p[0] = set(map(chr, range(begin, end+1)))
    def p_set_item_escape(self, p):
        """
        set_item : BACKSLASH RBRACKET
                 | BACKSLASH CARET
                 | BACKSLASH DASH
                 | BACKSLASH BACKSLASH
        """
        p[0] = set([p[2]])
    def p_set_item_escape_fallback(self, p):
        """
        set_item : BACKSLASH set_non_meta_char
        """
        if p[2] in character_classes:
            p[0] = set(character_classes[p[2]])
        else:
            p[0] = set(p[2])

    def p_set_non_meta_char(self, p):
        """
        set_non_meta_char : NON_META_CHAR
                          | LBRACKET
                          | DIGIT
                          | DOT
                          | STAR
                          | PLUS
                          | QUESTION
                          | BAR
                          | LPAREN
                          | RPAREN
                          | LBRACE
                          | RBRACE
                          | COMMA
                          | COLON
                          | DOLLAR
        """
        p[0] = p[1]

    def p_error(self, p):
        print ("Parse error at '%s'" % p.value)
        self.errors.append(p)

    def __init__(self):
        self.lexer = RegexLexer()
        self.tokens = self.lexer.tokens
        self.parser = yacc.yacc(module=self)

    def parse(self, s):
        self.groups = []
        self.backrefs = set()
        self.errors = []
        root = self.parser.parse(s, self.lexer.lexer)
        return {'groups': self.groups, 'backrefs': self.backrefs, 'root': root, 'errors': self.errors}
