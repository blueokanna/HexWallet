// Arguments: chain_probe, gaiad v14.2.0 and osmosisd v6.4.0. The independent
// @confio/relayer@0.12.0 and its CosmJS dependencies are loaded from NODE_PATH.
const assert = require('node:assert/strict');
const path = require('node:path');
const {setTimeout: delay} = require('node:timers/promises');
const {IbcClient} = require('@confio/relayer/build/lib/ibcclient');
const {Link} = require('@confio/relayer/build/lib/link');
const {DirectSecp256k1HdWallet} = require('@cosmjs/proto-signing');
const {GasPrice} = require('@cosmjs/stargate');
const {Order} = require('cosmjs-types/ibc/core/channel/v1/channel');
const {hub, osmosis, withNode, sendReviewed, testWords, sha256} = require('./cosmos_test_node.cjs');
const {buildIbcTransfer} = require('../../tools/cosmos_payment.cjs');

async function client(node) {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(testWords, {prefix: node.prefix});
  const [{address}] = await wallet.getAccounts();
  assert.equal(address, node.relayer);
  return IbcClient.connectWithSigner(node.endpoint, wallet, address, {gasPrice: GasPrice.fromString(`0.025${node.denom}`),
    estimatedBlockTime: 500, estimatedIndexerTime: 150, broadcastPollIntervalMs: 200});
}

function attributes(event) {
  const utf8 = str => Buffer.from(str, 'base64').toString('utf8');
  return Object.fromEntries(event.attributes.map(({key, value}) => [utf8(key), utf8(value)]));
}

async function packetEvent(node, height, type, packet) {
  const params = {height: String(height)};
  const [block, result] = await Promise.all([node.rpc('block', params), node.rpc('block_results', params)]);
  const index = result.txs_results.findIndex(tx => tx.code === 0 && tx.events.some(event => {
    if (event.type !== type) return false;
    const a = attributes(event);
    return a.packet_sequence === String(packet.sequence) && a.packet_src_channel === packet.sourceChannel && a.packet_dst_channel === packet.destinationChannel;
  }));
  assert.ok(index >= 0, `${node.chainId} ${type}`);
  return sha256(Buffer.from(block.block.data.txs[index], 'base64'));
}

async function payment(probe, link, side, source, dest, amount, expire = false) {
  const srcChannel = `channel-${source.firstChannel}`, destChannel = `channel-${dest.firstChannel}`;
  const voucher = 'ibc/' + sha256(`transfer/${destChannel}/${source.denom}`);
  const commitments = () => source.query('ibc', 'channel', 'packet-commitments', 'transfer', srcChannel).commitments;
  assert.deepEqual(commitments(), []);
  const initial = source.balance(source.sender), received = dest.balance(dest.recipient, voucher);
  const destTime = Date.parse((await dest.rpc('status')).sync_info.latest_block_time);
  const timeoutNs = BigInt(destTime + (expire ? 10000 : 300000)) * 1000000n;
  const sent = await sendReviewed(probe, source, buildIbcTransfer, 'ibcTransfer',
    [dest.recipient, `transfer/${srcChannel}`, dest.chainId, String(timeoutNs)], {amount, receiver: dest.recipient, timeoutNs});
  assert.equal(source.balance(source.sender), initial - amount - 2700n);
  const [commitment] = commitments();
  const [send] = sent.tx_result.events.filter(event => event.type === 'send_packet').map(attributes);
  const data = Buffer.from(send.packet_data_hex || Buffer.from(send.packet_data).toString('hex'), 'hex');
  const fields = JSON.parse(data);
  assert.equal(fields.denom, source.denom);
  assert.equal(fields.amount, String(amount));
  assert.equal(fields.sender, source.sender);
  assert.equal(fields.receiver, dest.recipient);
  assert.equal(send.packet_sequence, commitment.sequence);
  assert.equal(send.packet_timeout_timestamp, String(timeoutNs));
  assert.equal(send.packet_src_channel, srcChannel);
  assert.equal(send.packet_dst_channel, destChannel);
  const packet = {sourcePort: 'transfer', sourceChannel: srcChannel, destinationPort: 'transfer', destinationChannel: destChannel,
    sequence: BigInt(send.packet_sequence), data, timeoutHeight: {revisionNumber: 0n, revisionHeight: 0n}, timeoutTimestamp: timeoutNs};
  const packets = [{packet, height: Number(sent.height)}];
  const args = ['transfer', destChannel, String(packet.sequence)];
  if (expire) {
    const deadline = Date.now() + 30000;
    while (BigInt(Date.parse((await dest.rpc('status')).sync_info.latest_block_time)) * 1000000n <= timeoutNs) {
      assert.ok(Date.now() < deadline, 'destination block timestamp did not advance');
      await delay(250);
    }
    const height = await link.timeoutPackets(side, packets);
    const hash = await packetEvent(source, height, 'timeout_packet', packet);
    assert.deepEqual(commitments(), []);
    assert.equal(source.balance(source.sender), initial - 2700n);
    assert.equal(dest.balance(dest.recipient, voucher), received);
    assert.equal(dest.query('ibc', 'channel', 'packet-receipt', ...args).received, false);
    console.log(`${source.chainId} timeout seq=${packet.sequence} refund=${amount}${source.denom} height=${height} tx=${hash}`);
    return;
  }
  const acks = await link.relayPackets(side, packets);
  assert.equal(acks.length, 1);
  const [ack] = acks;
  assert.deepEqual(JSON.parse(Buffer.from(ack.acknowledgement)), {result: 'AQ=='});
  assert.equal(dest.balance(dest.recipient, voucher), received + amount);
  assert.equal(dest.query('ibc', 'channel', 'packet-receipt', ...args).received, true);
  const ackCommit = dest.query('ibc', 'channel', 'packet-ack', ...args).acknowledgement;
  assert.equal(Buffer.from(ackCommit, 'base64').toString('hex').toUpperCase(), sha256(ack.acknowledgement));
  const ackHeight = await link.relayAcks(side === 'A' ? 'B' : 'A', acks);
  assert.ok(ackHeight > Number(sent.height));
  assert.deepEqual(commitments(), []);
  assert.equal(await packetEvent(dest, ack.height, 'recv_packet', packet), ack.txHash);
  const ackHash = await packetEvent(source, ackHeight, 'acknowledge_packet', packet);
  console.log(`${source.chainId} -> ${dest.chainId} seq=${packet.sequence} received=${amount}${voucher} recv_height=${ack.height} recv_tx=${ack.txHash} ack_height=${ackHeight} ack_tx=${ackHash}`);
}

async function main() {
  const [probe, gaiad, osmosisd] = process.argv.slice(2).map(p => path.resolve(p));
  await withNode(gaiad, hub, a => withNode(osmosisd, osmosis, async b => {
    const ca = await client(a), cb = await client(b);
    try {
      const link = await Link.createWithNewConnections(ca, cb);
      const route = await link.createChannel('A', 'transfer', 'transfer', Order.ORDER_UNORDERED, 'ics20-1');
      assert.equal(route.src.channelId, 'channel-141');
      assert.equal(route.dest.channelId, 'channel-0');
      console.log(`IBC ${route.src.channelId} <-> ${route.dest.channelId} open`);
      await payment(probe, link, 'A', a, b, 1234567n);
      await payment(probe, link, 'B', b, a, 2345678n);
      await payment(probe, link, 'A', a, b, 3456789n, true);
    } finally { ca.sign.disconnect(); cb.sign.disconnect(); }
  }));
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
