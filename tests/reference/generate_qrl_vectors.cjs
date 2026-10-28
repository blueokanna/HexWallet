// Only public test inputs and PUBLIC keys/addresses are saved or printed.
// qrllib 1.3.2 is the independent legacy XMSS oracle, not firmware code.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const assert = require('node:assert/strict'), {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const qrl = require(path.join(root, 'build/qrl-reference/package/build/offline-libjsqrl.js'));
qrl.onRuntimeInitialized = () => {
  try {
    const cases = [];
    function add(name, input, height, index = null) {
      let treeSeed = Buffer.from(input);
      if (index !== null) {
        const suffix = Buffer.alloc(4); suffix.writeUInt32BE(index);
        const domain = index === 0 ? Buffer.from('HexWallet/QRL/v1') : Buffer.concat([Buffer.from('HexWallet/QRL/v2'), suffix]);
        treeSeed = crypto.createHash('shake256', {outputLength:48}).update(domain).update(input).digest();
      }
      const v = new qrl.Uint8Vector(); for (const b of treeSeed) v.push_back(b);
      const key = qrl.Xmss.fromParameters(v, height, qrl.eHashFunction.SHAKE_256);
      const c = {name, input:input.toString('hex'), height, index,
        public:key.getPK(), address:key.getAddress()};
      key.delete(); v.delete(); treeSeed.fill(0);
      cases.push(c);
      if (process.argv.includes('--verify-device')) {
        const result = spawnSync(path.join(root, 'build/chain-native/Release/chain_probe.exe'),
          [index === null ? 'qrl-vector' : 'qrl-mapped-vector', c.input, String(index ?? 0), String(height)], {encoding:'utf8'});
        assert.equal(result.status, 0, result.stdout + result.stderr);
        const actual = Object.fromEntries(result.stdout.trim().split(/\r?\n/).map(x=>x.split('=')));
        assert.equal(actual.public, c.public, name); assert.equal(actual.address, c.address, name);
      }
    }
    for (const height of [4,6]) {
      add('zero-'+height, Buffer.alloc(48), height);
      add('sequential-'+height, Buffer.from(Array.from({length:48},(_,i)=>i)), height);
    }
    for (const index of [0,1,17]) add('wallet-tree-'+index,Buffer.from(Array.from({length:64},(_,i)=>i)),4,index);
    const data = {test_only:true, source:'qrllib 1.3.2 offline-libjsqrl.js; legacy SHAKE256 XMSS', cases};
    const target = path.join(root,'tests/fixtures/qrl-sdk.json');
    if(process.argv.includes('--check')) assert.deepEqual(JSON.parse(fs.readFileSync(target)), data);
    else fs.writeFileSync(target, JSON.stringify(data,null,2)+'\n');
    console.log(`QRL: ${cases.length} independent public-key/address cases; no signing claim`);
    process.exit(0);
  } catch(e) { console.error(e); process.exit(1); }
};
