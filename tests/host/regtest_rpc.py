"""Run a test node against a fresh, private regtest data directory."""

import base64
import json
import secrets
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@contextmanager
def running_regtest(prepare, chain_name='regtest'):
    with tempfile.TemporaryDirectory(prefix='wallet-regtest-') as datadir:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        password = secrets.token_hex(24)
        authorization = 'Basic ' + base64.b64encode(f'test:{password}'.encode()).decode()

        def rpc(method, *params):
            body = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode()
            req = Request(f'http://127.0.0.1:{port}/', body, {'Authorization': authorization, 'Content-Type': 'application/json'})
            try:
                response = urlopen(req, timeout=180)
            except HTTPError as err:
                response = err
            with response:
                result = json.load(response, parse_float=Decimal)
            if result.get('error'):
                raise RuntimeError(f"{method}: {result['error']}")
            return result['result']

        args = prepare(Path(datadir), port, password)
        with tempfile.TemporaryFile() as log, subprocess.Popen(args, stdout=log, stderr=log) as node:
            try:
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline and node.poll() is None:
                    try:
                        if rpc('getblockchaininfo')['chain'] == chain_name:
                            break
                    except (URLError, ConnectionError, RuntimeError):
                        pass
                    time.sleep(0.2)
                else:
                    log.seek(0)
                    raise RuntimeError(log.read().decode(errors='replace')[-2500:])
                yield rpc
            finally:
                if node.poll() is None:
                    try:
                        rpc('stop')
                        node.wait(timeout=15)
                    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
                        node.kill()


def regtest(daemon, extra_args=()):
    def prepare(datadir, port, password):
        config = datadir / 'test.conf'
        config.write_text(f'rpcuser=test\nrpcpassword={password}\n', encoding='ascii')
        return [daemon, '-regtest', '-server', '-listen=0', '-listenonion=0', '-discover=0',
                '-dnsseed=0', '-connect=0', '-rpcbind=127.0.0.1', f'-rpcport={port}',
                f'-datadir={datadir}', f'-conf={config}', '-printtoconsole', *extra_args]
    return running_regtest(prepare)
