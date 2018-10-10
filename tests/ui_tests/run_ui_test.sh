#!/usr/bin/env bash


echo -n '^http://example.com$' | hack_url_re

# supposed to fail
echo -n '^http://example[0-9]com$' | hack_url_re --require-literal-dot-in-domain
