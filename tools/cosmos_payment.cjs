// Phone link kind 8. The device reconstructs the bank, IBC or authz message.
const {Buffer} = require('buffer');
const {serializeSignDoc} = require('@cosmjs/amino');
const {secp256k1} = require('@noble/curves/secp256k1');
const {sha256} = require('@noble/hashes/sha256');
const {ripemd160} = require('@noble/hashes/ripemd160');
const {bech32} = require('@scure/base');
const {AuthInfo, SignDoc, TxBody, TxRaw} = require('cosmjs-types/cosmos/tx/v1beta1/tx');
const {PubKey} = require('cosmjs-types/cosmos/crypto/secp256k1/keys');
const {MsgSend} = require('cosmjs-types/cosmos/bank/v1beta1/tx');
const {MsgGrant, MsgRevoke} = require('cosmjs-types/cosmos/authz/v1beta1/tx');
const {SendAuthorization} = require('cosmjs-types/cosmos/bank/v1beta1/authz');
const {MsgTransfer} = require('cosmjs-types/ibc/applications/transfer/v1/tx');

const networks = new Map([
  ['cosmoshub-4', {hrp: 'cosmos', denom: 'uatom', channel: 'channel-141'}],
  ['osmosis-1', {hrp: 'osmo', denom: 'uosmo', channel: 'channel-0'}],
]);
function text(value) {
  if (typeof value !== 'string' || !/^[a-z0-9-]{1,89}$/.test(value)) throw new Error('Invalid route or receiver');
  const bytes = Buffer.from(value, 'ascii');
  return Buffer.concat([Buffer.from([bytes.length]), bytes]);
}
function u64(value) {
  if (typeof value !== 'bigint' && !Number.isSafeInteger(value)) throw new Error('Expected an exact integer');
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}
function prefix(version, {chainId, account, sequence, fee, gas}) {
  if (!networks.has(chainId)) throw new Error('Unsupported Cosmos chain');
  return [Buffer.from([version]), text(chainId), u64(account), u64(sequence), u64(fee), u64(gas)];
}
function buildIbcTransfer(params) {
  return Buffer.concat([...prefix(4, params), u64(params.amount), text(params.receiver), text(networks.get(params.chainId).channel), u64(params.timeoutNs)]);
}
function buildAminoSend(params) {
  return Buffer.concat([...prefix(5, params), u64(params.amount), text(params.receiver)]);
}
function buildRevokeSend(params) {
  return Buffer.concat([...prefix(6, params), text(params.grantee)]);
}
function buildGrantSend(params) {
  return Buffer.concat([...prefix(7, params), u64(params.spendLimit), text(params.grantee), u64(params.expirySeconds)]);
}

function any(codec, fields) {
  return {typeUrl: codec.typeUrl, value: codec.encode(codec.fromPartial(fields)).finish()};
}

// Use the original phone proposal parameters and the selected account's public
// key. Rebuild the expected transaction independently of the device's RESULT.
async function broadcastCosmos({rpc, operation, params, signed, sender, publicKey}) {
  const {chainId, sequence, account, gas, fee} = params;
  const network = networks.get(chainId);
  if (!network || !(signed instanceof Uint8Array) || signed.length > 1664 ||
      !(publicKey instanceof Uint8Array) || publicKey.length !== 33 ||
      bech32.encode(network.hrp, bech32.toWords(ripemd160(sha256(publicKey)))) !== sender)
    throw new Error('Cosmos chain, signed transaction or sender mismatch');
  for (const value of [sequence, account, gas, fee]) u64(value);
  const coin = value => {
    u64(value);
    return {amount: String(value), denom: network.denom};
  };
  const fees = BigInt(fee) === 0n ? [] : [coin(fee)];
  const authority = {granter: sender, grantee: params.grantee};
  let message, aminoBytes;
  switch (operation) {
    case 'ibcTransfer':
      u64(params.timeoutNs);
      message = any(MsgTransfer, {sourcePort: 'transfer', sourceChannel: network.channel, token: coin(params.amount),
        sender, receiver: params.receiver, timeoutHeight: {}, timeoutTimestamp: BigInt(params.timeoutNs)});
      break;
    case 'aminoSend': {
      const amount = [coin(params.amount)];
      message = any(MsgSend, {fromAddress: sender, toAddress: params.receiver, amount});
      aminoBytes = serializeSignDoc({account_number: String(account), chain_id: chainId, sequence: String(sequence),
        fee: {amount: fees, gas: String(gas)}, memo: '', msgs: [{type: 'cosmos-sdk/MsgSend',
          value: {from_address: sender, to_address: params.receiver, amount}}]});
      break;
    }
    case 'grantSend':
      u64(params.expirySeconds);
      message = any(MsgGrant, {...authority, grant: {authorization: any(SendAuthorization, {spendLimit: [coin(params.spendLimit)]}),
        expiration: {seconds: BigInt(params.expirySeconds)}}});
      break;
    case 'revokeSend':
      message = any(MsgRevoke, {...authority, msgTypeUrl: MsgSend.typeUrl});
      break;
    default: throw new Error('Unsupported Cosmos broadcast operation');
  }
  const bodyBytes = TxBody.encode(TxBody.fromPartial({messages: [message]})).finish();
  const authInfoBytes = AuthInfo.encode(AuthInfo.fromPartial({fee: {amount: fees, gasLimit: BigInt(gas)}, signerInfos: [{
    publicKey: any(PubKey, {key: publicKey}), modeInfo: {single: {mode: aminoBytes ? 127 : 1}}, sequence: BigInt(sequence),
  }]})).finish();
  const signBytes = aminoBytes || SignDoc.encode({bodyBytes, authInfoBytes, chainId, accountNumber: BigInt(account)}).finish();
  const wire = Buffer.from(signed);
  const {signatures} = TxRaw.decode(wire);
  if (signatures.length !== 1 || signatures[0].length !== 64 ||
      !wire.equals(TxRaw.encode({bodyBytes, authInfoBytes, signatures}).finish()) ||
      !secp256k1.verify(signatures[0], sha256(signBytes), publicKey, {lowS: true}))
    throw new Error('Cosmos signature or reviewed transaction mismatch');
  if ((await rpc('status', {}))?.node_info?.network !== chainId) throw new Error('Cosmos RPC chain mismatch');
  const hash = Buffer.from(sha256(wire)).toString('hex').toUpperCase();
  // A sync reply reports mempool admission. The caller checks inclusion and
  // execution separately using this hash, including after a transport timeout.
  let result;
  try { result = await rpc('broadcast_tx_sync', {tx: wire.toString('base64')}); }
  catch (cause) { throw new Error(`Check Cosmos transaction ${hash} before retrying`, {cause}); }
  if (result?.code !== 0 || result?.hash?.toUpperCase() !== hash)
    throw new Error(`Cosmos broadcast returned code ${result?.code} for transaction ${hash}`);
  return hash;
}

module.exports = {buildIbcTransfer, buildAminoSend, buildRevokeSend, buildGrantSend, broadcastCosmos};
