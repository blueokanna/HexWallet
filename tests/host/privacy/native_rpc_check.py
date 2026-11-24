"""Check receive refusal, encoders against release binaries, and Ryo relay at private genesis."""
import argparse
from contextlib import ExitStack, contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from payment_interop import FIXTURES, ROOT


def post(port, route, body):
    req = Request(f'http://127.0.0.1:{port}/{route}', json.dumps(body).encode(),
                  {'Content-Type': 'application/json'})
    with urlopen(req, timeout=10) as response:
        return json.load(response)


@contextmanager
def offline_node(daemon, ryo, *, directory=None, network=None, height=1):
    if network not in (None, 'testnet', 'stagenet') or (network and not ryo):
        raise ValueError('Unsupported local node profile')
    storage = nullcontext(str(directory)) if directory else tempfile.TemporaryDirectory(prefix='hexwallet-node-')
    with storage as folder, tempfile.TemporaryFile() as log:
        with ExitStack() as sockets:
            ports = []
            for _ in range(3 if ryo else 2):
                s = sockets.enter_context(socket.socket())
                s.bind(('127.0.0.1', 0))
                ports.append(str(s.getsockname()[1]))
        args = [str(daemon.resolve()), '--data-dir', folder, '--p2p-bind-ip', '127.0.0.1',
                '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', ports[0], '--p2p-bind-port', ports[1]]
        if ryo:
            args += ['--offline', '--no-igd', '--disable-dns-checkpoints', '--check-updates', 'disabled',
                     '--zmq-rpc-bind-port', ports[2], '--log-file', str(Path(folder) / 'ryo.log')]
            if network:
                args += ['--' + network, '--fast-block-sync', '0']
        else:
            args += ['--offline-mode', '--no-predownload', '--disable-ntp', '--disable-upnp', '--rpc-ignore-offline']
        with subprocess.Popen(args, cwd=folder, stdin=subprocess.PIPE, stdout=log, stderr=log) as node:
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline and node.poll() is None:
                    try:
                        if post(ports[0], 'getheight', {}).get('height') == height:
                            break
                    except (URLError, OSError, ValueError, KeyError):
                        pass
                    time.sleep(.2)
                else:
                    log.seek(0)
                    raise RuntimeError(f'Failed to start {daemon.name}: {log.read()[-1500:]!r}')
                yield ports[0]
            finally:
                if node.poll() is None:
                    try:
                        node.communicate(b'exit\n', timeout=12)
                    except (OSError, subprocess.TimeoutExpired):
                        node.kill()
                        node.wait()


def check_ryo_relay(probe, port):
    with tempfile.TemporaryDirectory() as folder:
        wire, context = [Path(folder) / name for name in ('wire', 'context')]
        for case in json.loads(FIXTURES.read_text())['spends']:
            wire.write_bytes(bytes.fromhex(case['wire']))
            context.write_bytes(bytes.fromhex(case['context']))
            fields = dict(line.split('=', 1) for line in subprocess.check_output(
                [str(probe), 'privacy-ryo-spend', str(wire), str(context)], text=True, timeout=120).splitlines())
            assert hashlib.sha256(bytes.fromhex(fields['signed'])).hexdigest() == case['signed_sha256']
            result = post(port, 'sendrawtransaction', {'tx_as_hex': fields['signed'], 'do_not_relay': True})
            assert (result['status'], result.get('invalid_output'), result.get('reason')) == (
                'Failed', True, 'invalid output'), result
            pool = post(port, 'get_transaction_pool', {})
            assert pool['status'] == 'OK' and not pool.get('transactions'), pool
            print(f"ryod height 1, {case['signed_sha256']}: {result['reason']}, mempool empty")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'ryod', 'ryo-validator', 'zanod'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('Checks require Python assertions')
    probe = args.probe.resolve()
    with offline_node(args.zanod, False) as port:
        subprocess.run(['node', str(Path(__file__).with_name('address_interop.cjs').resolve()), str(probe),
                        '--ryo-validator', str(args.ryo_validator.resolve()), '--zano-rpc-port', port],
                       env={**os.environ, 'NODE_PATH': str(ROOT / 'tests/host/protocol-oracles/node_modules')}, check=True)
    with offline_node(args.ryod, True) as port:
        check_ryo_relay(probe, port)


if __name__ == '__main__':
    main()
