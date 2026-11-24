// Wallet-side adapter for one top-level DApp origin and one authenticated phone link.
const {Buffer} = require('buffer');
const {getAddress, getBytes, hexlify, toQuantity, Transaction} = require('ethers');
const {broadcastEthereum} = require('./phone_broadcast.cjs');

function error(code, message) { return Object.assign(new Error(message), {code}); }

const readMethods = new Set(['eth_blockNumber', 'eth_call', 'eth_estimateGas', 'eth_feeHistory',
  'eth_gasPrice', 'eth_getBalance', 'eth_getBlockByHash', 'eth_getBlockByNumber', 'eth_getCode',
  'eth_getLogs', 'eth_getStorageAt', 'eth_getTransactionByHash', 'eth_getTransactionCount',
  'eth_getTransactionReceipt', 'eth_maxPriorityFeePerGas']);
const transactionKeys = new Set(['from', 'to', 'value', 'gas', 'gasPrice', 'nonce', 'type', 'chainId',
  'data', 'input', 'maxFeePerGas', 'maxPriorityFeePerGas', 'accessList']);

function quantity(value) {
  if (typeof value !== 'string' || !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value))
    throw error(-32602, 'Expected a hexadecimal JSON-RPC quantity');
  return BigInt(value);
}

async function serializeRequest(tx, sender, chainId, rpc) {
  if (!tx || typeof tx !== 'object' || Array.isArray(tx) || Object.keys(tx).some(k => !transactionKeys.has(k)))
    throw error(-32602, 'Unsupported transaction field');
  if (typeof tx.from !== 'string' || getAddress(tx.from) !== sender) throw error(4100, 'Unauthorized sender');
  if (tx.chainId !== undefined && quantity(tx.chainId) !== chainId) throw error(4901, 'Wrong transaction chain');
  if (tx.input !== undefined && tx.data !== undefined && hexlify(tx.input) !== hexlify(tx.data))
    throw error(-32602, 'Conflicting data and input');

  const dynamicFee = tx.maxFeePerGas !== undefined || tx.maxPriorityFeePerGas !== undefined;
  const type = tx.type === undefined ? (dynamicFee ? 2 : tx.accessList === undefined ? 0 : 1) : Number(quantity(tx.type));
  if (![0, 1, 2].includes(type) || (type === 0 && tx.accessList !== undefined) ||
      (dynamicFee && type !== 2) || (type === 2 && tx.gasPrice !== undefined))
    throw error(-32602, 'Inconsistent transaction type and fees');
  const fields = {type, chainId, data: hexlify(tx.data ?? tx.input ?? '0x'),
    to: tx.to == null ? null : getAddress(tx.to), value: tx.value === undefined ? 0n : quantity(tx.value)};
  if (type !== 0) fields.accessList = tx.accessList ?? [];
  if (type === 2) {
    fields.maxPriorityFeePerGas = quantity(tx.maxPriorityFeePerGas ?? await rpc('eth_maxPriorityFeePerGas', []));
    fields.maxFeePerGas = tx.maxFeePerGas === undefined
      ? 2n * quantity((await rpc('eth_getBlockByNumber', ['latest', false])).baseFeePerGas) + fields.maxPriorityFeePerGas
      : quantity(tx.maxFeePerGas);
    if (fields.maxPriorityFeePerGas > fields.maxFeePerGas) throw error(-32602, 'Priority fee exceeds maximum fee');
  } else fields.gasPrice = quantity(tx.gasPrice ?? await rpc('eth_gasPrice', []));
  const nonce = quantity(tx.nonce ?? await rpc('eth_getTransactionCount', [sender, 'pending']));
  if (nonce > BigInt(Number.MAX_SAFE_INTEGER)) throw error(-32602, 'Nonce too large');
  fields.nonce = Number(nonce);
  const estimate = {...tx, from: sender, data: fields.data};
  delete estimate.input;
  fields.gasLimit = quantity(tx.gas ?? await rpc('eth_estimateGas', [estimate]));
  return Transaction.from(fields).unsignedSerialized;
}

// The wallet supplies the browser-observed origin, the permission prompt, its RPC,
// and exchange(plaintext, signal) over an already paired, authenticated link.
// Give the DApp only `provider`. Destroy this instance on navigation or wallet lock.
function createEthereumConnection({origin, approveOrigin, exchange, rpc, index = 0}) {
  const url = new URL(origin);
  if (url.origin !== origin || url.protocol !== 'https:' || typeof approveOrigin !== 'function' ||
      typeof exchange !== 'function' || typeof rpc !== 'function' || !Number.isInteger(index) || index < 0 || index >= 2 ** 31)
    throw new TypeError('Invalid Ethereum wallet connection');
  const chainId = 1n;
  const events = new Map();
  const controller = new AbortController();
  let account, busy = false, sequence = 0;
  const current = () => { if (controller.signal.aborted) throw error(4900, 'Wallet disconnected'); };
  async function checkedRpc(method, params) {
    current();
    const result = await rpc(method, params);
    // Once submitted, return the node's acknowledgement even if the page closed in flight.
    if (method !== 'eth_sendRawTransaction') current();
    if (method === 'eth_chainId' && quantity(result) !== chainId) throw error(4901, 'Wrong RPC network');
    return result;
  }
  const emit = (name, value) => { for (const fn of [...(events.get(name) ?? [])]) { try { fn(value); } catch {} } };
  const network = Buffer.concat([Buffer.from([3]), Buffer.from('eth')]);
  const word = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

  async function device(op, parts) {
    current();
    const id = ++sequence;
    const reply = Buffer.from(await exchange(Buffer.concat([Buffer.from([op]), word(id), ...parts]), controller.signal));
    current();
    if (reply.length < 5 || reply.readUInt32LE() !== id) throw error(-32603, 'Mismatched wallet reply');
    const status = reply[4];
    if (status === 2) throw error(4001, 'Device rejected the review');
    if (status === 9) throw error(4100, 'Wallet is locked');
    if (status > 1) throw error(-32603, `Device status ${status}`);
    return {status, body: reply.subarray(5)};
  }

  async function connect() {
    if (account) return [account];
    const allowed = await approveOrigin(origin, controller.signal);
    current();
    if (allowed !== true) throw error(4001, 'Connection declined');
    await checkedRpc('eth_chainId', []);
    const {status, body} = await device(4, [network, word(0), word(0), word(index)]);
    const path = `m/44'/60'/0'/0/${index}`;
    if (status !== 0 || body[0] !== 42 || body[43] !== path.length || body.length !== 44 + path.length ||
        body.toString('latin1', 44) !== path) throw error(-32603, 'Unexpected device address or path');
    account = getAddress(body.toString('latin1', 1, 43));
    emit('accountsChanged', [account]);
    return [account];
  }

  async function send(tx) {
    if (!account) throw error(4100, 'Account access requires permission');
    const sender = account;
    await checkedRpc('eth_chainId', []);
    let unsigned;
    try { unsigned = await serializeRequest(tx, sender, chainId, checkedRpc); }
    catch (err) {
      if (err.code === 'INVALID_ARGUMENT') throw error(-32602, err.shortMessage);
      throw err;
    }
    const wire = Buffer.from(getBytes(unsigned));
    if (wire.length + 16 > 16384) throw error(-32602, 'Transaction exceeds phone link capacity');
    const length = Buffer.alloc(2);
    length.writeUInt16LE(wire.length);
    const pending = await device(5, [network, Buffer.from([2]), word(index), length, wire]);
    if (pending.status !== 1 || pending.body.length !== 8) throw error(-32603, 'Invalid review ID');
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline) {
      const {status, body} = await device(6, [pending.body]);
      if (status === 0) {
        if (body.length < 3 || body.readUInt16LE() !== body.length - 2) throw error(-32603, 'Invalid signed result');
        return broadcastEthereum({sender, chainId, unsigned, signed: body.subarray(2),
          rpc: checkedRpc});
      }
      if (body.length) throw error(-32603, 'Invalid pending reply');
      await new Promise(resolve => setTimeout(resolve, 350));
    }
    // CANCEL returns the same status as a decision made on the device.
    try { await device(7, [pending.body]); } catch (err) { if (err.code !== 4001) throw err; }
    throw error(-32603, 'Device review expired');
  }

  const provider = Object.freeze({
    async request({method, params = []}) {
      current();
      if (!Array.isArray(params)) throw error(-32602, 'Expected positional parameters');
      if (method === 'eth_chainId' || method === 'net_version') {
        await checkedRpc('eth_chainId', []);
        return method === 'eth_chainId' ? toQuantity(chainId) : String(chainId);
      }
      if (method === 'eth_accounts') return account ? [account] : [];
      if (readMethods.has(method)) { await checkedRpc('eth_chainId', []); return checkedRpc(method, params); }
      if (!['eth_requestAccounts', 'eth_sendTransaction'].includes(method)) throw error(4200, 'Unsupported wallet method');
      if (busy) throw error(-32002, 'Wallet request pending');
      if (params.length !== (method === 'eth_requestAccounts' ? 0 : 1)) throw error(-32602, 'Unexpected parameters');
      busy = true;
      try { return method === 'eth_requestAccounts' ? await connect() : await send(structuredClone(params[0])); }
      finally { busy = false; }
    },
    on(name, fn) {
      if (typeof fn !== 'function') throw new TypeError('Expected event listener');
      if (!events.has(name)) events.set(name, new Set());
      events.get(name).add(fn);
      return provider;
    },
    removeListener(name, fn) { events.get(name)?.delete(fn); return provider; },
  });

  return {provider, disconnect() {
    if (controller.signal.aborted) return;
    controller.abort();
    account = undefined;
    emit('accountsChanged', []);
    emit('disconnect', error(4900, 'Wallet disconnected'));
    events.clear();
  }};
}

// Register with EIP-6963 DApp discovery in the page-facing part of the wallet.
// The wallet supplies its own PNG data URI and calls the returned cleanup on navigation.
function announceEthereumProvider(target, provider, icon) {
  if (typeof icon !== 'string' || !/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(icon))
    throw new TypeError('Expected a wallet PNG data URI');
  const info = Object.freeze({uuid: target.crypto.randomUUID(), name: 'HexWallet', icon,
    rdns: 'com.github.blueokanna.hexwallet'});
  const detail = Object.freeze({info, provider});
  const announce = () => target.dispatchEvent(new target.CustomEvent('eip6963:announceProvider', {detail}));
  target.addEventListener('eip6963:requestProvider', announce);
  announce();
  return () => target.removeEventListener('eip6963:requestProvider', announce);
}

module.exports = {createEthereumConnection, announceEthereumProvider};
