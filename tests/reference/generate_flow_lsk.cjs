// Public test seed; independent ethers parser, signer recovery and serialization.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const {HDNodeWallet, Transaction, Interface, parseUnits} = require(path.join(root, 'build/nem-sdk/node_modules/ethers'));
const seed = Buffer.from(Array.from({length:64}, (_, i) => i));
const token = '0x6033F7f88332B8db6ad452B7C6D5bB643990aE3f';
const recipient = '0x1111111111111111111111111111111111111111';
const abi = new Interface(['function transfer(address,uint256)']);
const cases = [], rejected = [];
for (const index of [0, 1, 17]) {
  const wallet = HDNodeWallet.fromSeed(seed).derivePath(`m/44'/60'/0'/0/${index}`);
  for (const network of ['flow-evm', 'eth']) {
    const native = network === 'flow-evm';
    const tx = Transaction.from({type:0, chainId:native ? 747 : 1, nonce:3,
      gasPrice:1000000000n, gasLimit:native ? 21000 : 65000,
      to:native ? recipient : token, value:native ? parseUnits('1.23456789',18) : 0,
      data:native ? '0x' : abi.encodeFunctionData('transfer',[recipient,parseUnits('1.23456789',18)])});
    const c = {name:`${network}-${index}`, network, index, seed:seed.toString('hex'),
      address:wallet.address.toLowerCase(), recipient, amount:'1.23456789',
      asset:native ? 'FLOW' : 'LSK', fee_asset:native ? 'FLOW' : 'ETH',
      fee:native ? '0.000021' : '0.000065', hash:tx.unsignedHash.slice(2),
      payload:tx.unsignedSerialized.slice(2)};
    cases.push(c);
    if (process.argv.includes('--verify-device')) {
      const p = spawnSync(path.join(root,'build/chain-native/Release/chain_probe.exe'),
        [network,c.seed,c.payload,String(index)], {encoding:'utf8'});
      assert.equal(p.status,0,p.stdout+p.stderr);
      const actual = Object.fromEntries(p.stdout.trim().split(/\r?\n/).map(x=>x.split('=')));
      for (const field of ['address','recipient','amount','fee','hash','asset','fee_asset']) assert.equal(actual[field],c[field],c.name+':'+field);
      const signed = Transaction.from('0x'+actual.signed);
      assert.equal(signed.from.toLowerCase(),c.address);
      assert.equal(signed.unsignedSerialized,tx.unsignedSerialized);
      assert.equal(signed.unsignedHash,tx.unsignedHash);
      assert(signed.signature.isValid());
    }
    const wrong = tx.clone(); wrong.chainId = native ? 1 : 747;
    rejected.push({...c,name:c.name+'-wrong-chain',payload:wrong.unsignedSerialized.slice(2)});
  }
}
const data = {test_only:true,source:'ethers 6.15.0; Flow network and official Ethereum LSK contract',cases,rejected};
const target = path.join(root,'tests/fixtures/flow-lsk-sdk.json');
if(process.argv.includes('--check')) assert.deepEqual(JSON.parse(fs.readFileSync(target)),data);
else fs.writeFileSync(target,JSON.stringify(data,null,2)+'\n');
console.log(`Flow EVM / Ethereum LSK: ${cases.length} cases, ${rejected.length} wrong-network cases`);
