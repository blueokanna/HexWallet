// Arguments: chain_probe, node binary and optional profile (atom or osmo).
const assert = require('node:assert/strict');
const path = require('node:path');
const {hub, osmosis, withNode, sendReviewed} = require('./cosmos_test_node.cjs');
const {buildAminoSend, buildRevokeSend, buildGrantSend} = require('../../tools/cosmos_payment.cjs');

async function main() {
  const [probe, daemon] = process.argv.slice(2, 4).map(p => path.resolve(p));
  const profile = process.argv[4] || 'atom';
  assert.ok(['atom', 'osmo'].includes(profile));
  await withNode(daemon, profile === 'atom' ? hub : osmosis, async node => {
    const {sender, recipient, query, balance, denom} = node;
    const grants = () => query('authz', 'grants', sender, recipient).grants;
    const amount = 1234567n, fee = 2700n;
    const expirySeconds = BigInt(Math.floor(Date.now() / 1000) + 86400);
    const initial = balance(sender);
    assert.equal(initial, 100000000n);
    assert.deepEqual(grants(), []);
    await sendReviewed(probe, node, buildAminoSend, 'aminoSend', ['LEGACY AMINO JSON'], {amount, receiver: recipient});
    assert.equal(balance(recipient), amount);
    assert.equal(balance(sender), initial - amount - fee);
    await sendReviewed(probe, node, buildGrantSend, 'grantSend', ['GRANT BANK SEND'], {grantee: recipient, spendLimit: amount, expirySeconds});
    const [grant] = grants();
    assert.equal(grant.authorization['@type'], '/cosmos.bank.v1beta1.SendAuthorization');
    assert.deepEqual(grant.authorization.spend_limit, [{denom, amount: String(amount)}]);
    assert.equal(Date.parse(grant.expiration), Number(expirySeconds) * 1000);
    await sendReviewed(probe, node, buildRevokeSend, 'revokeSend', ['REVOKE BANK SEND'], {grantee: recipient});
    assert.deepEqual(grants(), []);
    assert.equal(balance(sender), initial - amount - 3n * fee);
    assert.equal(balance(recipient), amount);
    console.log(`verified ${amount} ${denom} received, ${3n * fee} ${denom} in fees, grant limit and expiry stored, grant removed`);
  });
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
