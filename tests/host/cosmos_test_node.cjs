// Local SDK node shared by the Gaia payment and two-chain IBC checks.
const assert = require('node:assert/strict');
const {execFileSync, spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const {once} = require('node:events');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const {setTimeout: delay} = require('node:timers/promises');
const {broadcastCosmos} = require('../../tools/cosmos_payment.cjs');

const testWords = 'abandon '.repeat(11) + 'about';
const hub = {chainId: 'cosmoshub-4', network: 'atom', denom: 'uatom', prefix: 'cosmos', firstChannel: 141};
const osmosis = {chainId: 'osmosis-1', network: 'osmo', denom: 'uosmo', prefix: 'osmo', firstChannel: 0};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex').toUpperCase();

async function withNode(binary, profile, run) {
  const {chainId, denom, firstChannel} = profile;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `wallet-${profile.network}-`));
  const cli = (args, input) => execFileSync(binary, [...args, '--home', dir], {
    encoding: 'utf8', input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000,
  });
  let proc, stopped;
  try {
    cli(['init', 'wallet-validator', '--chain-id', chainId]);
    const key = (name, index) => {
      const options = ['--keyring-backend', 'test'];
      const recovery = index === undefined ? [] : ['--recover', '--index', String(index)];
      cli(['keys', 'add', name, '--no-backup', ...options, ...recovery], recovery.length ? testWords + '\n' : undefined);
      return cli(['keys', 'show', name, '-a', ...options]).trim();
    };
    const validator = key('validator'), relayer = key('relayer', 0);
    const sender = key('sender', 3), recipient = key('recipient', 4);
    const publicKey = Buffer.from(JSON.parse(cli(['keys', 'show', 'sender', '--pubkey', '--keyring-backend', 'test'])).key, 'base64');
    const genesisPath = path.join(dir, 'config', 'genesis.json');
    const genesis = JSON.parse(fs.readFileSync(genesisPath));
    // Advance only the channel identifier counter. Clients, connections and
    // channel ends must be created by real handshakes after genesis.
    const channels = genesis.app_state.ibc.channel_genesis;
    assert.equal(channels.channels.length, 0);
    channels.next_channel_sequence = String(firstChannel);
    const bond = genesis.app_state.staking.params.bond_denom;
    fs.writeFileSync(genesisPath, JSON.stringify(genesis, (field, value) =>
      ['denom', 'bond_denom', 'mint_denom', 'basedenom'].includes(field) && value === bond ? denom : value));
    for (const [addr, amount] of [[validator, 1000000000], [sender, 100000000], [relayer, 100000000]])
      cli(['add-genesis-account', addr, `${amount}${denom}`]);
    cli(['gentx', 'validator', `100000000${denom}`, '--keyring-backend', 'test', '--chain-id', chainId]);
    cli(['collect-gentxs']);
    cli(['validate-genesis']);
    const cfg = path.join(dir, 'config', 'config.toml');
    fs.writeFileSync(cfg, fs.readFileSync(cfg, 'utf8').replace(/^timeout_commit\s*=.*$/m, 'timeout_commit = "500ms"')
      .replace(/^(seeds|persistent_peers|pprof_laddr)\s*=.*$/gm, '$1 = ""'));
    // Old Osmosis enables its REST server by default. These checks use RPC.
    const app = path.join(dir, 'config', 'app.toml');
    fs.writeFileSync(app, fs.readFileSync(app, 'utf8').replace(/(\[api\][^[]*?\benable\s*=\s*)true/, '$1false')
      .replace('tcp://0.0.0.0:1317', 'tcp://127.0.0.1:0'));
    const server = net.createServer().listen(0, '127.0.0.1');
    await once(server, 'listening');
    const port = server.address().port, endpoint = `http://127.0.0.1:${port}`;
    await new Promise(resolve => server.close(resolve));
    const rpc = async (method, params = {}) => {
      const response = await fetch(endpoint, {method: 'POST', signal: AbortSignal.timeout(15000),
        headers: {'content-type': 'application/json'}, body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params})});
      assert.ok(response.ok, `${method} HTTP ${response.status}`);
      const result = await response.json();
      if (result.error) throw new Error(JSON.stringify(result.error));
      return result.result;
    };
    const logPath = path.join(dir, 'node.log'), log = fs.openSync(logPath, 'w');
    try {
      proc = spawn(binary, ['start', '--home', dir, '--rpc.laddr', `tcp://127.0.0.1:${port}`,
        '--p2p.laddr', 'tcp://127.0.0.1:0', '--p2p.pex=false', '--grpc.enable=true', '--grpc.address', '127.0.0.1:0', '--grpc-web.enable=false',
        '--minimum-gas-prices', `0${denom}`], {stdio: ['ignore', log, log]});
      stopped = once(proc, 'exit');
    } finally { fs.closeSync(log); }
    const deadline = Date.now() + 45000;
    for (;;) {
      if (proc.exitCode !== null || Date.now() > deadline) throw new Error(fs.readFileSync(logPath, 'utf8').slice(-4000));
      let status;
      try { status = await rpc('status'); } catch { await delay(200); continue; }
      assert.equal(status.node_info.network, chainId);
      if (Number(status.sync_info.latest_block_height) > 1) break;
      await delay(200);
    }
    console.log(`${chainId} genesis=${sha256(fs.readFileSync(genesisPath))}`);
    const query = (...args) => JSON.parse(cli(['query', ...args, '--node', endpoint, '-o', 'json']));
    const balance = (addr, asset = denom) => BigInt(query('bank', 'balances', addr).balances.find(c => c.denom === asset)?.amount || 0);
    return await run({...profile, endpoint, rpc, query, balance, sender, recipient, publicKey, relayer});
  } finally {
    try {
      if (proc && proc.exitCode === null) proc.kill();
      if (stopped) await stopped;
    } finally { fs.rmSync(dir, {recursive: true, force: true, maxRetries: 3}); }
  }
}

async function sendReviewed(probe, node, build, operation, labels, extra) {
  const {rpc, query, sender, publicKey, chainId} = node;
  const account = query('auth', 'account', sender);
  const params = {chainId, account: BigInt(account.account_number), sequence: BigInt(account.sequence), fee: 2700n, gas: 200000, ...extra};
  const payload = build(params);
  const review = execFileSync(probe, ['phone-review', node.network, payload.toString('hex'), 'approve'], {encoding: 'utf8'}).trim().split(/\r?\n/);
  for (const label of [...labels, `address=${sender}`]) assert.ok(review.includes(label), label);
  const signed = Buffer.from(review.find(line => line.startsWith('signed=')).slice(7), 'hex');
  const hash = sha256(signed);
  assert.equal(await broadcastCosmos({rpc, signed, sender, publicKey, operation, params}), hash);
  const deadline = Date.now() + 30000;
  let indexed;
  while (!indexed) {
    try { indexed = await rpc('tx', {hash: Buffer.from(hash, 'hex').toString('base64')}); }
    catch (error) {
      if (Date.now() >= deadline || !/not found/i.test(error.message)) throw error;
      await delay(200);
    }
  }
  assert.equal(indexed.tx_result.code, 0, indexed.tx_result.log);
  const block = await rpc('block', {height: indexed.height});
  assert.equal(indexed.tx, signed.toString('base64'));
  assert.ok(block.block.data.txs.includes(indexed.tx));
  console.log(`${operation} height=${indexed.height} tx=${hash} block=${block.block_id.hash}`);
  return indexed;
}

module.exports = {hub, osmosis, withNode, sendReviewed, testWords, sha256};
