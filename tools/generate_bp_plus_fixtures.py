"""Turns tests/fixtures/monero-bp-plus into a C++ include for the host test.

The fixtures are produced by tests/reference/monero_reference.cpp, which links
the pinned Monero tree and never this firmware. Regenerating the include is
therefore a one-way flow: reference output in, firmware test data out.

Usage:
    python tools/generate_bp_plus_fixtures.py            # rewrite the include
    python tools/generate_bp_plus_fixtures.py --check     # verify it is current
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, 'tests', 'fixtures', 'monero-bp-plus')
TARGET = os.path.join(ROOT, 'src', 'generated', 'BulletproofPlusReferenceTest.inc')

FIELDS = ('A', 'A1', 'B', 'r1', 's1', 'd1')
INTERMEDIATES = ('initial', 'V_hash', 'after_V', 'y', 'z', 'e', 'sum_y', 'multiexp')


def load():
    with open(os.path.join(FIXTURES, 'manifest.json'), encoding='utf-8') as handle:
        manifest = json.load(handle)
    cases = []
    for entry in manifest['cases']:
        path = os.path.join(FIXTURES, entry['name'] + '.json')
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
            # The reference generator writes numeric fields as strings.
            data['count'] = int(data['count'])
            data['rounds'] = int(data['rounds'])
            if data['count'] != entry['count']:
                raise SystemExit('count mismatch in ' + entry['name'])
            if data['rounds'] != 6 + _log2_ceil(entry['count']):
                raise SystemExit('rounds mismatch in ' + entry['name'])
            cases.append(data)
    return manifest, cases


def _log2_ceil(count):
    log = 0
    while (1 << log) < count:
        log += 1
    return log


def emit(manifest, cases):
    lines = []
    lines.append('// Bulletproofs+ reference vectors, generated. Do not edit.')
    lines.append('//')
    lines.append('// Source: %s %s (%s)' % (
        manifest['source'], manifest['version'], manifest['commit']))
    lines.append('// Producer: %s' % manifest['generator'])
    lines.append('// The proofs, commitments and intermediate transcript values below')
    lines.append('// come from Monero\'s own prover and verifier. This firmware never')
    lines.append('// produced them, so matching them is evidence and not self-consistency.')
    lines.append('//')
    lines.append('// Shape per entry:')
    lines.append('//   commitments, rounds, V[16], A, A1, B, r1, s1, d1, L[10], R[10],')
    lines.append('//   initial, V_hash, after_V, y, z, challenges[10], e, sum_y, multiexp')
    lines.append('')
    for case in cases:
        lines.append('  {')
        lines.append('    %d, // commitments' % case['count'])
        lines.append('    %d, // rounds' % case['rounds'])
        lines.append('    { // V')
        for index in range(case['count']):
            lines.append('      {%s},' % _bytes(case['V_%d' % index]))
        lines.append('    },')
        for field in FIELDS:
            lines.append('    {%s}, // %s' % (_bytes(case[field]), field))
        lines.append('    { // L')
        for index in range(case['rounds']):
            lines.append('      {%s},' % _bytes(case['L_%d' % index]))
        lines.append('    },')
        lines.append('    { // R')
        for index in range(case['rounds']):
            lines.append('      {%s},' % _bytes(case['R_%d' % index]))
        lines.append('    },')
        for name in INTERMEDIATES:
            lines.append('    {%s}, // %s' % (_bytes(case[name]), name))
        lines.append('    { // challenges')
        for index in range(case['rounds']):
            lines.append('      {%s},' % _bytes(case['challenge_%d' % index]))
        lines.append('    },')
        lines.append('  },')
    return '\n'.join(lines) + '\n'


def _bytes(hex_text):
    raw = bytes.fromhex(hex_text)
    if len(raw) != 32:
        raise SystemExit('expected a 32-byte value, got %d' % len(raw))
    return ','.join('0x%02x' % byte for byte in raw)


def main():
    manifest, cases = load()
    text = emit(manifest, cases)
    if '--check' in sys.argv:
        try:
            with open(TARGET, encoding='utf-8') as handle:
                current = handle.read()
        except FileNotFoundError:
            print('missing ' + os.path.relpath(TARGET, ROOT))
            return 1
        if current != text:
            print('stale: ' + os.path.relpath(TARGET, ROOT))
            return 1
        print('up to date: %d vectors' % len(cases))
        return 0
    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    with open(TARGET, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)
    print('wrote %s (%d vectors)' % (os.path.relpath(TARGET, ROOT), len(cases)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
