from hack_url_re.solving import *

DEBUG = True


example = r"^http://(m.)?example\.com(?:$|/|\?)"
example2 = r"^http://(m.)?example.com(?:/|\?)"
example3 = r"http://(m.)?example.com(?:/|\?)"
example4 = r".*http://example\.com/.*"
example5 = r"^http://.+\.example\.com/.*"
example6 = r'^https://ab\d+cd\.example\.com/xyz/lmn'
example7 =  r'^https://x\.y\.com/\w+/example/xyz.com'
example7b =  r'^https://x\.y\.com//example/xyz.com'
example7c =  r'^https://x\.y\.com/\w+'
example8 = r'^https://www\.(?:abc|xyz)\.com(?:$|/)'
example8b = r'^https://www\.(a|b)\.com($|/)'
example8c = r'^https://www\.(a|b)\.com'
example9 = r"h..ps://."
example10 = r".....+"
example11 = r".*.*.*.*.*.*.*.*" * 2
example11b = r"a"
example11c = r""
example12 = r"^https://a\.com/"
example13 = r"^https://[^/]a\.com/.*"
example14 = r"^https://[^/]*\.a\.com/.*"
example15 = r"^https://[/abcdefghij]*\.a\.com/$"
example15b = r"^https://[/a-z]*\.a\.com/"
example15c = r"^https://[abcdefghij]*\.a\.com/[abcdefghij]*"
example15d = r"^https://[/.abcdef0123]*"
example15e = r"^https://[^^]*$"
example15f = r"^https://[abcdefghijk]$"


example16 = r"^https://[^\.]*\.example\.com(?:$|/)"
example16a = r"^https://[^\.]\.example\.com(?:$|/)"    # no hack, but should warn on possible zero domain

example17 = r"http\:\/\/x\.y\.z\.com\/\/ABCD\.\?PARAM\=VAL.+"


if False:
    for ex in [example4]:
        found_domains, unknown, warnings = hack_url_regex(ex,
                                                        #lengths=range(23, 35),
                                                        #lengths=range(25, 35),
                                                        callback=print_callback,
                                                        max_total_finds=10,
                                                        max_finds_per_length=50,
        )# lengths=range(40, 41))
        print('found {} domains:'.format(len(found_domains)))
        print(found_domains)
        print('unknown?', unknown)

        if warnings:
            print('WARNING:')
            for ww in warnings:
                print('  - ', end='')
                print(ww)



if True:
    strategy = combination_wildcard_and_find_n
    #strategy = wildcard_trace
    for ex in [
            example7,
            #example, example2, example3, example4, example5, example6, example7, example8,
            #example9, example10, example11,
            #example,
            #example12,
            #example13,
            #example14,
            #example11b,
            #example11c,
            #example15,
            #example15c,
            #example15d,
            #example15e,
            example16,
            #example17,
    ]:
        print('-'*50)
        print('solving ex:', ex)
        solver = z3.Solver()

        with solver_frame(solver):
            add_regex_constraints(solver, r'.*' + ex + r'.*')
            result, evidence = strategy(solver)

        warnings = get_warnings(ex)

        if result == z3.sat:
            print('found evidence: base_url: {}'.format(evidence))
        else:
            print('no attack found. root domains found:', evidence)
            print('unknown?', result == z3.unknown)

        if warnings:
            print('WARNING:')
            for ww in warnings:
                print('  - ', end='')
                print(ww)
