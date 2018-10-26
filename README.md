# hack\_url\_re -- Hack URL Regex Automatically With Z3

Automatically hacks regex for identifying domains from URLs. It compiles regex and attack
definitions into logical statements for the Z3 solver.

Suppose an app identifies resources on certain web domains by applying a regex to urls. The regex
may contain a mistake, causing the app to misidentify websites. For example,
`^https://\w+.example\.com$` is supposed to only accept urls under the domain example.com, but it
accepts `https://evilexample.com`. An attacker could buy `evilexample.com` and acquire a certificate
for it, then masquerade as `example.com` to the app. (More examples below.) It is especially
important for password managers, such as the Okta plugin, to properly identify websites.

The `hack_url_re` tool will automatically hack url regexes. The main idea is to translate the
regex into constraints on a URL string, define the structure of a url, then ask if there can be
wildcards in the fully qualified domain name (FQDN) or if there are many solutions for the domain.

See the Methods section for more details.


## Why not $ALTERNATIVE?

Z3 has native regex support, but:

- Z3 does not have a regex parser.
- Z3 does not handle carets and dollars.
- z3.Star performs relatively slowly. This may be due to its unboundedness. `hack_url_re`
  approximates Star with finite choices.
- In informal testing, typical regex took ten times less time for hack_url_re to analyze than
  with the native Z3 regex.

regex-crossword-solver:

- regex-crossword-solver is meant for solving known-length strings.
- regex-crossword-solver's string representation is an array of integers. This representation is not
  compatible with Z3's theory of strings, which are very useful for defining the structure of a URL.
- regex-crossword-solver has limited support for carets and dollars. They can only be at the beginning
  and end of the URL. For example, it cannot handle `https://example.com($|/.*)`.
  (Both the parser and z3-expression-translator have this limitation.)

grep-like tool that just searches for things like missing carets (`^`) and unquoted dots (`.`):

- The grep-like tool would have trouble with false positives for regex like
  `^https://example\.com/.*`, which has an unquoted dot in a safe place. It would also have trouble
  deciding if the dot in something like `\\.` is quoted or not.
- For patterns with the caret in a group, like `(^https://example|https://example2)\.com$`, a simple
  search is not enough to determine whether the attacker could control the beginning of the URL.
- Patterns like `^https://m[^/]*example\.com$` would confuse a tool that does not understand regex.

In contrast,

- hack_url_re has approximations for Stars and character sets, to reduce the search space without
  loss of generality.
- hack_url_re uses Z3's theory of strings to describe URL structure
- hack_url_re implements caret and dollar in arbitrary locations
- as opposed to a grep-like tool, hack_url_re understands regex.

In short, hack_url_re is a better fit to the problem of hacking URL regexes.


## Requirements

- ply
- z3
- toolz
- pytest (optional -- for testing)


## Installation

Clone this repo. Then, in the top level directory for the repo, run

~~~
`pip install .`
~~~

Tips: run `pip install -e` to install in place. Use the `--user` flag to install to your home directory.


## Usage

The `hack_url_re` CLI takes a regex from stdin and outputs a JSON report to stdout. The output
contains the satisfiability result, which is one of

- "sat": a successful attack was found
- "unsat": no attack is possible, given the attack definitions (assuming there is no bug in
  `hack_url_re` of course)
- "unknown": inconclusive results

If the result is "sat", then the output will include a "witness", which is useful in validating the
attack.


### Examples:

This does a quick attack (see Method 1 below).
~~~
$ echo -n '^https://.*example\.com$' | hack_url_re -q
{
    "result": "sat",
    "solution": "https://☠☠☠☠example.com",
    "strategy": "wildcard_trace",
    "witness": "https://☠☠☠☠example.com"
}
~~~
Note that the pattern matching searches the entire string, not just the beginning. I.e. it follows
Python's `re.search`, as `re.match`.

To do a full attack, which includes Method 2, leave off the '-q' option, like in the following:
~~~
$ echo -n '^https://[a-z]example\.com\.$' | hack_url_re --require-dot-in-domain
{
    "result": "sat",
    "solution": "https://zexample.com.",
    "strategy": "find_n_root_domains_ignoring_wildcards",
    "found": ["https://aexample.com.", "https://iexample.com.", "https://mexample.com.", "https://nexample.com.",
              "https://dexample.com.", "https://texample.com.", "https://eexample.com.", "https://fexample.com.",
              "https://rexample.com.", "https://zexample.com."]
    ],
    "witness": ["aexample.com", "iexample.com", "mexample.com", "nexample.com", "dexample.com",
                "texample.com", "eexample.com", "fexample.com", "rexample.com", "zexample.com"]
}
~~~
This also requires a dot to be in the domain. Also note the DNS root at the end; it is correctly
recognized as part a valid part of the FQDN.

The time it takes to solve varies. If the above example takes longer than 10 minutes, try restarting it.

Run `hack_url_re -h` for help.


## Support

The tool supports a subset of Extended Regular Expressions. It supports

- Wildcards: '.'
- Endings: '^', '$'
- Quantifiers: '+', '*'
- Groups: '(', ')'
- Sets: '[', ']'
- Optionals: '?'
- Some special character sets: '\d', '\w'

Notably missing are lookaheads, lookbacks, and group references, although these would not be
difficult to add in the compilation framework.


## Methods

### Method 1 (Quick)

Tries to get a '☠' (a skull emoji -- or other configurable taint marker) anywhere in the domain or
protocol. Since emoji are not valid url characters, and none of the sets like \d, \a, \w, or even
[^/] have emoji in them (they are excluded from the [^X] charsets by fiat), emoji can only show up
if there was a wildcard (unquoted dot). A wildcard in the protocol or domain is trouble. If it's in
the protocol, there's a possibility to do something like `{evil_url}/{good_url}`. If a wildcard is
in the domain, even a subdomain, the attacker could insert a `/` and make their domain come before
the `/`.

In addition to more exploitable patterns, this method will report patterns that accept strings like
this: `https://☠.example.com`. It does not appear to be exploitable, as putting a `/` in for the
wildcard would give an empty domain, but it is probably worth fixing to be more restrictive anyway.
This method will also report patterns accepting strings like `https://example.com:☠`, in which the
attacker controls only the port. This hasn't been much of an issue so far in our usage.


### Method 2 (Slow)

Try to find N root domains that match a URL regex (in practice, N is set to 10). If N are found,
then it's a bad regex. (For example, the domain in `www.example.com` is `example.com`, it doesn't
include anything prior to that.)

In addition to vulnerable patterns, this method will report URLs with domains that don't have
dots in them. For example, the pattern `^https://[^\.]\.example.com$` accepts
`https://evil/example.com'. This isn't very exploitable because it would be difficult to obtain a
certificate for a domain without a dot in it. However, in my opinion it is still worth fixing so
hack_url_re will report it.

Root domains with country code TLDs (CC TLDs) are somewhat tricky to deal with because they can
result in either two or three levels in the root domain. The Find N strategy first tries to find N
two-level domains. If it fails to find N such domains, but it found a domain with a CC TLD, it will
then try to find three-level domains until it reaches N total two-level and three-level domains,
ignoring any two-level domains that are suffixes of the three-level domains.


### Combining 1 and 2

Since Method 1 doesn't find any hacks that don't rely on a wildcard (unquoted dot), it is good to
combine it with Method 2 as a fallback. When we running Method 2 as a fallback, we can ignore all
wildcards, since we cover all wildcard-based hacks in Method 1.



## Bad URL regex examples

- `https://example\.com/$` -- has no ^. The output will be `☠☠☠☠https://example.com/`. Attacker could put `https://evil.com/` in
place of the ☠☠☠☠.

- `https://.*\.example\.com/$` -- Dot in the FQDN. The output will be `https://☠☠☠☠example.com/`. Attacker could put `evil.com/` in place of the ☠☠☠☠

- `https://(m.)?\.example\.com/$` -- Possible dot in the FQDN. The output will be `https://m☠example.com/`. Attacker could put `a` in place of the ☠ to make the domain `maexample.com`


## Caveats

- hack_url_re assumes URLs already have the basic auth portion stripped out of all
  URLs. Therefore `https://evil.com@example.com` is not considered a valid hack. This
  could be implemented but was not necessary for Okta's use case.


## Troubleshooting

- Sometimes hack_url_re gets stuck, and it can help to restart. It seems that
  Z3 can get into a bad state.


## Attribution

Many thanks to Yunjong Jeong for regex-crossword-solver. This project started off as a modification
of that project. Although the translation into z3 expressions was rewritten, the parser is from
regex-crossword-solver is largely intact.
