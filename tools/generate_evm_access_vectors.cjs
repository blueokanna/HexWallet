// Development-only oracle. Firmware and normal fixture checks do not use JS.
// Input: official ethers v6.15.0 dist/ethers.umd.min.js, SHA-256 below.
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const source = path.resolve(process.argv[2] || 'build/evm-reference/ethers.cjs');
const digest = crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex');
if (digest !== 'fcfd9597005606eabed524ed9f97df69dbc5cac461119a9bb8a4c6b280cfa3f1') throw Error('Unexpected ethers source');
const e = require(source);
const seed = '0x' + '00'.repeat(64);
const wallet = new e.Wallet(e.HDNodeWallet.fromSeed(seed).derivePath("m/44'/60'/0'/0/0").privateKey);
const address = '0x' + '35'.repeat(20);
const slot = n => e.zeroPadValue(e.toBeHex(n), 32);
const tx = (type, accessList) => ({type, chainId: 1, nonce: 1,
  ...(type === 2 ? {maxPriorityFeePerGas: 1000000000n, maxFeePerGas: 2000000000n}
                 : {gasPrice: 2000000000n}),
  gasLimit: 65000, to: address, value: 1n, data: '0x', accessList});
const valid = [];
async function addValid(type, name, list, overrides = {}) {
  const input = {...tx(type, list), ...overrides};
  const transaction = e.Transaction.from(input);
  const signed = await wallet.signTransaction(input);
  if (e.Transaction.from(signed).from.toLowerCase() !== wallet.address.toLowerCase())
    throw Error('Oracle signature recovery mismatch');
  const review = list.length === 0 ? '' : 'ACCESS LIST (gas scheduling)\n' +
    list.map(([account, keys]) => account + '\n' + keys.map(key => '  ' + key + '\n').join('')).join('');
  const details = `EIP-${type === 1 ? '2930' : '1559'}\nCHAIN ID 1\nFROM\n${wallet.address.toLowerCase()}\n` +
    `NONCE ${input.nonce}\nGAS LIMIT ${input.gasLimit}\n` +
    (type === 1 ? `GAS PRICE ${input.gasPrice} WEI\n` :
      `MAX GAS PRICE ${input.maxFeePerGas} WEI\nMAX PRIORITY ${input.maxPriorityFeePerGas} WEI\n`) +
    (input.data === '0x' ? '' : `CONTRACT\n${input.to.toLowerCase()}\nCALL\nERC-20.transfer\n`) + review;
  valid.push({name: `type${type}-${name}`, type, unsigned: transaction.unsignedSerialized.slice(2),
    hash: transaction.unsignedHash.slice(2), signed: signed.slice(2),
    addresses: list.length, keys: list.reduce((n, row) => n + row[1].length, 0), review, details});
}
async function main() {
  const invalid = [];
  for (const type of [1, 2]) {
  for (const [name, list] of [
    ['empty', []], ['address-only', [[address, []]]],
    ['two-slots', [[address, [slot(0), slot(1)]]]],
    ['duplicates-preserved', [[address, [slot(1), slot(1)]], [address, []]]],
    ['eight-addresses', Array.from({length: 8}, () => [address, []])],
    ['eight-slots', [[address, Array.from({length: 8}, (_, i) => slot(i))]]]
  ]) {
    await addValid(type, name, list);
  }
  await addValid(type, 'usdc-transfer', [[address, [slot(0)]]], {
    to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', value: 0n,
    data: new e.Interface(['function transfer(address,uint256)']).encodeFunctionData('transfer', [address, 1000000n])
  });
  const rawFields = e.decodeRlp('0x' + valid.find(c => c.name === `type${type}-two-slots`).unsigned.slice(2));
  const accessIndex = type === 2 ? 8 : 7;
  const gasIndex = type === 2 ? 4 : 3;
  const destinationIndex = gasIndex + 1;
  const add = (name, accessList, field, value) => {
    const fields = structuredClone(rawFields);
    fields[accessIndex] = accessList;
    if (field !== undefined) fields[field] = value;
    invalid.push({name: `type${type}-${name}`, unsigned: `0${type}` + e.encodeRlp(fields).slice(2)});
  };
  add('access-list-string', '0x');
  add('entry-string', [address]);
  add('address-19', [['0x' + '35'.repeat(19), []]]);
  add('address-21', [['0x' + '35'.repeat(21), []]]);
  add('keys-string', [[address, '0x']]);
  add('key-31', [[address, ['0x' + '01'.repeat(31)]]]);
  add('key-33', [[address, ['0x' + '01'.repeat(33)]]]);
  add('nested-key', [[address, [[slot(1)]]]]);
  add('extra-entry-field', [[address, [], '0x']]);
  add('nine-addresses', Array.from({length: 9}, () => [address, []]));
  add('nine-slots', [[address, Array.from({length: 9}, (_, i) => slot(i))]]);
  add('oversized-list', [[address, Array.from({length: 12}, (_, i) => slot(i))]]);
  add('intrinsic-gas-short', [[address, [slot(0), slot(1)]]], gasIndex, e.toBeHex(27199));
  add('wrong-chain', [[address, []]], 0, '0x02');
  if (type === 2) add('tip-over-cap', [], 2, e.toBeHex(3000000000));
  add('contract-creation', [], destinationIndex, '0x');
  add('unknown-calldata', [], destinationIndex + 2, '0xdeadbeef');
  add('zero-gas-price', [], gasIndex - 1, '0x');
  add('noncanonical-nonce', [], 1, '0x0001');
  invalid.push({name: `type${type}-signed-envelope`,
    unsigned: valid.find(c => c.name === `type${type}-empty`).signed});
  }
  for (const type of [0, 3, 4, 127]) {
    invalid.push({name: `unsupported-envelope-${type}`,
      unsigned: type.toString(16).padStart(2, '0') + valid[0].unsigned.slice(2)});
  }
  const report = {source: 'https://github.com/ethers-io/ethers.js/blob/v6.15.0/dist/ethers.umd.min.js',
    sha256: digest, version: e.version, seed: seed.slice(2), path: "m/44'/60'/0'/0/0",
    sender: wallet.address.toLowerCase(), valid, invalid};
  fs.mkdirSync('tests/fixtures', {recursive: true});
  fs.writeFileSync('tests/fixtures/evm-access-list.json', JSON.stringify(report, null, 2) + '\n');
  console.log(`Ethers ${e.version}: ${valid.length} valid, ${invalid.length} invalid access-list fixtures`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
