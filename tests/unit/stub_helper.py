#!/usr/bin/env python3
"""Stand-in for the dnshelper binary.

Logs argv, the environment names/values and the stdin request to STUB_LOG
(one JSON line per call) and answers from the JSON file STUB_RESPONSES, which
maps an op to the response document.
"""
import json
import os
import sys

req = json.load(sys.stdin)
with open(os.environ['STUB_LOG'], 'a') as f:
    f.write(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ), 'req': req}) + '\n')
responses = json.load(open(os.environ['STUB_RESPONSES']))
resp = responses[req['op']]
if isinstance(resp, str):  # raw output, for garbage tests
    sys.stdout.write(resp)
    sys.exit(1)
json.dump(resp, sys.stdout)
sys.exit(0 if resp.get('ok') else 1)
