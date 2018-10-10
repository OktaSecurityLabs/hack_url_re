# Code Overview

The heiearchy of layers from bottom up is

1. `parsing.py` -- parses regexes represented as ordinary Python strings into AST.
2. `preprocessing.py` -- transforms AST into more convenient form.
3. `compiling.py` -- compiles preprocessed regex AST into Z3 expressions.
4. `solving.py` -- combines vuln definitions with regex expressions, defines approximations and strategies.
5. `ui.py` and `batch_processing.py` -- user interfaces.
