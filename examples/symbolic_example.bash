
# The following usually takes less than 5 minutes on a 3.1 GHz Intel Core i7 (2017 MBP).
# Without --symbolic it takes a very long time.
time echo -n '^https://example(a|b|c|d|aaaaaaaaaaa|abcdefghijklmnop|x|y|z)\.com$' | hack_url_re --symbolic
