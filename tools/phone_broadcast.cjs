// Phone-side broadcast after RESULT. Supply an RPC client for the selected
// network. rpc(method, params) resolves to the JSON-RPC result or throws.
// Both functions return the transaction ID accepted by the RPC node.
const {getAddress, getBytes, hexlify, Transaction} = require('ethers');
const {getCompiledTransactionMessageCodec} = require('@solana/transaction-messages');
const {ed25519} = require('@noble/curves/ed25519');
const bs58 = require('bs58');
const {Buffer} = require('buffer');

async function broadcastEthereum({rpc, unsigned, signed, sender, chainId}) {
  const wire = hexlify(signed);
  const transaction = Transaction.from(wire);
  const expectedChain = BigInt(chainId);
  if (!transaction.isSigned() || transaction.serialized !== wire ||
      transaction.unsignedSerialized !== hexlify(unsigned) || transaction.from !== getAddress(sender) ||
      expectedChain <= 0n || transaction.chainId !== expectedChain)
    throw new Error('Ethereum signature, sender, chain or reviewed transaction mismatch');
  if (BigInt(await rpc('eth_chainId', [])) !== expectedChain) throw new Error('Ethereum RPC chain mismatch');
  const hash = await rpc('eth_sendRawTransaction', [wire]);
  if (typeof hash !== 'string' || hash.toLowerCase() !== transaction.hash)
    throw new Error(`Check Ethereum transaction ${transaction.hash} before retrying`);
  return transaction.hash;
}

async function broadcastSolana({rpc, unsigned, signed, payer, genesisHash}) {
  const wire = Buffer.from(getBytes(signed));
  if (wire.length <= 65 || wire.length > 1232 || wire[0] !== 1) throw new Error('Expected one Solana signature');
  const signature = wire.subarray(1, 65);
  const message = wire.subarray(65);
  if (!message.equals(getBytes(unsigned))) throw new Error('Solana reviewed message mismatch');
  const codec = getCompiledTransactionMessageCodec();
  const transaction = codec.decode(message);
  if ((transaction.version !== 'legacy' && transaction.version !== 0) ||
      transaction.header.numSignerAccounts !== 1 || transaction.staticAccounts[0] !== payer ||
      !message.equals(codec.encode(transaction)) || !ed25519.verify(signature, message, bs58.decode(payer), {zip215: false}))
    throw new Error('Solana signature, payer or reviewed message mismatch');
  if (typeof genesisHash !== 'string' || bs58.decode(genesisHash).length !== 32 ||
      await rpc('getGenesisHash', []) !== genesisHash) throw new Error('Solana RPC cluster mismatch');
  const validity = await rpc('isBlockhashValid', [transaction.lifetimeToken, {commitment: 'confirmed'}]);
  if (validity?.value !== true) throw new Error('Solana blockhash expired or unknown');
  const id = bs58.encode(signature);
  const accepted = await rpc('sendTransaction', [wire.toString('base64'), {
    encoding: 'base64', preflightCommitment: 'confirmed', skipPreflight: false,
  }]);
  if (accepted !== id) throw new Error(`Check Solana signature ${id} before retrying`);
  return id;
}

module.exports = {broadcastEthereum, broadcastSolana};
