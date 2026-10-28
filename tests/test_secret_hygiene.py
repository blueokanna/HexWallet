"""Guards for private-key and mnemonic handling.

These are static checks, not a proof of absence: they pin the invariants that
are cheap to verify and expensive to get wrong.

* key material must never reach a serial/printf sink outside the opt-in export
  block of WalletCli.cpp, and that block must stay off by default;
* secure_zero must not be implementable as an elidable memset;
* every seed buffer in the signing pipeline must be wiped on the way out.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

PRINT_SINK = re.compile(
    r'\b(Serial\.print(?:ln)?|::printf|printf|snprintf|fputs|puts|'
    r'print_hex(?:_reverse)?)\s*\(')
SECRET_IDENT = re.compile(
    r'(private_key|chain_code|mnemonic|bip39_seed|qrl_seed|sk_seed|'
    r'spend_secret|master_private|master_secret|seed_hex|secret_key)')
FUNCTION_START = re.compile(r'^[A-Za-z_][\w:<>\*&\s]*\b(\w+)\s*\(')

# WalletCli.cpp may echo secrets only from the functions that implement the
# opt-in `wallet secret` command; the command itself sits behind
# HEXWALLET_ENABLE_SECRET_EXPORT, which the next test pins to 0.
ALLOWED_CLI_FUNCTIONS = {'print_derived', 'show_addresses'}


def source_files():
    for pattern in ('*.cpp', '*.h', '*.ino'):
        for path in sorted(ROOT.glob(pattern)):
            yield path


class SecretHygieneTests(unittest.TestCase):
    def test_no_key_material_reaches_a_print_sink(self):
        offenders = []
        for path in source_files():
            lines = path.read_text(encoding='utf8', errors='replace').splitlines()
            current = ''
            for number, line in enumerate(lines, 1):
                match = FUNCTION_START.match(line)
                if match and path.name != 'WalletCli.cpp':
                    current = match.group(1)
                elif match:
                    current = match.group(1)
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                if not PRINT_SINK.search(line):
                    continue
                # Only a printed *expression* matters; literals such as
                # "RINGCT_FAIL derive_secret_key" or a help string that mentions
                # <mnemonic> carry no key material.
                code = re.sub(r'"(\\.|[^"\\])*"', '""', line)
                if not SECRET_IDENT.search(code):
                    continue
                if path.name == 'WalletCli.cpp' and current in ALLOWED_CLI_FUNCTIONS:
                    continue
                offenders.append('%s:%d: %s' % (path.name, number, stripped))
        self.assertEqual(offenders, [], 'secret printed to a log sink:\n' +
                         '\n'.join(offenders))

    def test_secret_export_is_off_by_default(self):
        config = (ROOT / 'WalletConfig.h').read_text(encoding='utf8')
        match = re.search(
            r'#ifndef\s+HEXWALLET_ENABLE_SECRET_EXPORT\s*\n#define\s+'
            r'HEXWALLET_ENABLE_SECRET_EXPORT\s+(\S+)', config)
        self.assertIsNotNone(match, 'HEXWALLET_ENABLE_SECRET_EXPORT default missing')
        self.assertEqual(match.group(1).strip('()'), '0',
                         'secret export must default to disabled')

    def test_secure_zero_cannot_be_optimised_away(self):
        source = (ROOT / 'WalletSecurity.cpp').read_text(encoding='utf8')
        body = re.search(r'void secure_zero\([^)]*\)\s*\{(.*?)\n\}', source, re.S)
        self.assertIsNotNone(body, 'secure_zero implementation missing')
        self.assertIn('mbedtls_platform_zeroize', body.group(1),
                      'secure_zero must use mbedtls_platform_zeroize')
        self.assertNotIn('memset', body.group(1),
                         'memset can be elided before the buffer dies')

    def test_signing_pipeline_wipes_every_seed_buffer(self):
        source = (ROOT / 'WalletSigning.cpp').read_text(encoding='utf8')
        declared = len(re.findall(r'uint8_t\s+seed\[kSeedSize\]', source))
        wiped = len(re.findall(r'secure_zero\(seed\b', source))
        self.assertGreater(declared, 0)
        self.assertGreaterEqual(
            wiped, declared,
            'each seed buffer needs a secure_zero on every exit path')

    def test_chain_dispatch_clears_derived_keys(self):
        source = (ROOT / 'ChainTransaction.cpp').read_text(encoding='utf8')
        declared = len(re.findall(r'DerivedAddress\s+derived\b', source))
        cleared = len(re.findall(r'clear_derived_address\(&derived\)', source))
        self.assertGreater(declared, 0)
        self.assertGreaterEqual(cleared, 2 * declared,
                                'review and sign must clear both success and '
                                'failure paths')

    def test_host_facing_link_layer_holds_no_key_material(self):
        for name in ('WalletLink.cpp', 'WalletLinkService.cpp', 'WalletLinkCrypto.cpp'):
            source = (ROOT / name).read_text(encoding='utf8')
            for match in SECRET_IDENT.finditer(source):
                line = source.count('\n', 0, match.start()) + 1
                text = source.splitlines()[line - 1].strip()
                self.fail('%s:%d holds key material: %s' % (name, line, text))


if __name__ == '__main__':
    unittest.main()
