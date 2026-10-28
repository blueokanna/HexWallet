// Independent CSL 15.0.3 oracle. Only PUBLIC TEST seeds; never accepts wallet data.
// Install: pnpm --dir build/cardano-sdk add --save-exact --ignore-scripts
//          @emurgo/cardano-serialization-lib-nodejs@15.0.3
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const C = require(path.join(root, 'build/cardano-sdk/node_modules/@emurgo/cardano-serialization-lib-nodejs'));
const pkg = require(path.join(root, 'build/cardano-sdk/node_modules/@emurgo/cardano-serialization-lib-nodejs/package.json'));
assert.equal(pkg.version, '15.0.3');
const hex = x => Buffer.from(x).toString('hex');
const bn = x => C.BigNum.from_str(String(x));
const hmac = (hash, data) => crypto.createHmac(hash, 'ed25519 seed').update(data).digest();
// CIP-0003 Ledger root, then CSL performs ALL child derivation and signing.
function master(seed) {
  const cc = hmac('sha256', Buffer.concat([Buffer.from([1]), seed]));
  let expanded = hmac('sha512', seed);
  while (expanded[31] & 32) expanded = hmac('sha512', expanded);
  expanded[0] &= 248; expanded[31] = (expanded[31] & 127) | 64;
  return C.Bip32PrivateKey.from_bytes(Buffer.concat([expanded, cc]));
}
function account(seed, index) {
  const a = master(seed).derive(0x8000073c).derive(0x80000717).derive(0x80000000);
  const payment = a.derive(0).derive(index).to_raw_key();
  const stake = a.derive(2).derive(0).to_raw_key();
  const address = C.BaseAddress.new(1,
    C.Credential.from_keyhash(payment.to_public().hash()),
    C.Credential.from_keyhash(stake.to_public().hash())).to_address();
  return {payment, address};
}
function cbHead(major, value) {
  const v = BigInt(value);
  if (v < 24n) return Buffer.from([(major << 5) | Number(v)]);
  const n = v <= 255n ? 1 : v <= 65535n ? 2 : v <= 0xffffffffn ? 4 : 8;
  const out = Buffer.alloc(n+1); out[0] = (major<<5) | (24 + Math.log2(n));
  for (let i=0; i<n; i++) out[n-i] = Number((v >> BigInt(8*i)) & 255n);
  return out;
}
function cbor(x) {
  if (Buffer.isBuffer(x)) return Buffer.concat([cbHead(2,x.length),x]);
  if (Array.isArray(x)) return Buffer.concat([cbHead(4,x.length),...x.map(cbor)]);
  if (x instanceof Map) return Buffer.concat([cbHead(5,x.size),...[...x].flatMap(([k,v])=>[cbor(k),cbor(v)])]);
  return cbHead(0,x);
}
const seeds = [
  crypto.pbkdf2Sync('abandon '.repeat(11)+'about','mnemonic',2048,64,'sha512'),
  Buffer.from(Array.from({length:64},(_,i)=>i)),
];
const recipient = C.EnterpriseAddress.new(1,
  C.Credential.from_keyhash(C.Ed25519KeyHash.from_bytes(Buffer.alloc(28,0x22)))).to_address();
const cases = [], rejected = [];
for (const [s, seed] of seeds.entries()) for (const index of [0,1,17]) {
  const {payment,address} = account(seed,index);
  for (const tagged of [false,true]) for (const change of [false,true]) {
    const inputs = C.TransactionInputs.new();
    inputs.add(C.TransactionInput.new(C.TransactionHash.from_bytes(Buffer.alloc(32,0x11)),3));
    const outputs = C.TransactionOutputs.new();
    outputs.add(C.TransactionOutput.new(recipient,C.Value.new(bn(1234567))));
    if(change) outputs.add(C.TransactionOutput.new(address,C.Value.new(bn(8000000))));
    const b = C.TransactionBody.new_tx_body(inputs,outputs,bn(180000));
    b.set_ttl(bn(200000000)); b.set_validity_start_interval_bignum(bn(199999000));
    b.set_network_id(C.NetworkId.mainnet());
    let body = Buffer.from(b.to_bytes());
    if (!tagged) {
      assert.equal(body.subarray(2,5).toString('hex'),'d90102');
      body = Buffer.concat([body.subarray(0,2),body.subarray(5)]);
    }
    const tx = C.FixedTransaction.new_from_body_bytes(body);
    tx.sign_and_add_vkey_signature(payment);
    const digest = tx.transaction_hash().to_bytes();
    const witness = tx.witness_set().vkeys().get(0);
    assert(payment.to_public().verify(digest,witness.signature()));
    // A freshly created witness set uses Conway tag 258. Match input set tagging
    // for the older encoding too; both are valid per the ledger CDDL/CIP-21.
    let signed = Buffer.from(tx.to_bytes());
    if (!tagged && signed.subarray(1+body.length+2,1+body.length+5).equals(Buffer.from('d90102','hex')))
      signed = Buffer.concat([signed.subarray(0,1+body.length+2),signed.subarray(1+body.length+5)]);
    C.FixedTransaction.from_bytes(signed); // independent complete transaction decode
    cases.push({name:`seed${s}-index${index}-${tagged?'tagged':'legacy'}-${change?'change':'single'}`,
      network:'ada',seed:hex(seed),index,payload:hex(body),address:address.to_bech32(),
      recipient:recipient.to_bech32(),amount:'1.234567 ADA',fee:'0.18 ADA',
      hash:hex(digest),signed:hex(signed),public:hex(payment.to_public().as_bytes())});
  }
}
// Babbage map output variant, independently decoded by CSL.
const a = account(seeds[0],0);
const simple = () => new Map([[0,[[Buffer.alloc(32,0x11),3]]],
  [1,[[Buffer.from(recipient.to_bytes()),1234567]]],[2,180000],[3,200000000]]);
for (const variant of ['map-output','eight-inputs','u64-slot','base-recipient']) {
  const b = simple();
  if(variant==='map-output') b.set(1,[new Map([[0,Buffer.from(recipient.to_bytes())],[1,1234567]])]);
  if(variant==='eight-inputs') b.set(0,Array.from({length:8},(_,i)=>[Buffer.alloc(32,i+1),i]));
  if(variant==='u64-slot') b.set(3,5000000000n);
  if(variant==='base-recipient') b.set(1,[[Buffer.from(account(seeds[0],1).address.to_bytes()),1234567]]);
  const body=cbor(b), tx=C.FixedTransaction.new_from_body_bytes(body);
  tx.sign_and_add_vkey_signature(a.payment);
  const digest=tx.transaction_hash().to_bytes(), sig=a.payment.sign(digest).to_bytes();
  const signed=Buffer.concat([Buffer.from([0x84]),body,Buffer.from('a10081825820','hex'),
    a.payment.to_public().as_bytes(),Buffer.from('5840','hex'),sig,Buffer.from('f5f6','hex')]);
  C.FixedTransaction.from_bytes(signed);
  cases.push({name:variant,network:'ada',seed:hex(seeds[0]),index:0,payload:hex(body),
    address:a.address.to_bech32(),recipient:C.TransactionBody.from_bytes(body).outputs().get(0).address().to_bech32(),
    amount:'1.234567 ADA',fee:'0.18 ADA',hash:hex(digest),signed:hex(signed),public:hex(a.payment.to_public().as_bytes())});
}
function bad(name, mutate) {
  const b=simple(); mutate(b);
  rejected.push({name,network:'ada',seed:hex(seeds[0]),index:0,payload:hex(cbor(b))});
}
bad('wrong-network', b => { const addr=Buffer.from(recipient.to_bytes());addr[0]=0x60;b.set(1,[[addr,1234567]]); });
bad('unowned-change', b => b.set(1,[b.get(1)[0],b.get(1)[0]]));
bad('zero-amount', b=>b.get(1)[0][1]=0);
bad('over-supply', b=>b.get(1)[0][1]=45000000000000001n);
bad('fee-too-high', b=>b.set(2,10000001));
bad('duplicate-input', b=>b.set(0,[b.get(0)[0],b.get(0)[0]]));
bad('unsorted-inputs', b=>b.set(0,[[Buffer.alloc(32,0x22),0],b.get(0)[0]]));
bad('nine-inputs', b=>b.set(0,Array.from({length:9},(_,i)=>[Buffer.alloc(32,i+1),i])));
bad('no-ttl', b=>b.delete(3));
bad('zero-ttl', b=>b.set(3,0));
bad('reversed-interval', b=>b.set(8,200000000));
bad('network-id-testnet', b=>b.set(15,0));
bad('staking', b=>b.set(4,[]));
bad('mint', b=>b.set(9,new Map()));
bad('metadata', b=>b.set(7,Buffer.alloc(32)));
bad('datum', b=>b.get(1)[0].push(Buffer.alloc(32)));
bad('multiasset', b=>b.get(1)[0][1]=[1234567,new Map()]);
bad('script-address', b=>{const adr=Buffer.from(recipient.to_bytes());adr[0]=0x71;b.set(1,[[adr,1234567]]);});
const result={source:'EMURGO/cardano-serialization-lib',version:pkg.version,
  root_standard:'CIP-0003 Ledger/BitBox02 (BIP39 seed)',test_only:true,cases,rejected};
const dest=path.join(root,'tests/fixtures/cardano-sdk.json');
if (process.argv.includes('--check')) assert.deepEqual(JSON.parse(fs.readFileSync(dest)),result);
else fs.writeFileSync(dest,JSON.stringify(result,null,2)+'\n');
if(process.argv.includes('--verify-device')) for(const c of cases) {
  const p=spawnSync(path.join(root,'build/chain-native/Release/chain_probe.exe'),
    ['ada',c.seed,c.payload,String(c.index)],{encoding:'utf8'});
  assert.equal(p.status,0,p.stdout+p.stderr);
  const rows=Object.fromEntries(p.stdout.trim().split(/\r?\n/).map(x=>x.split('=')));
  for(const key of ['address','recipient','amount','fee','hash','signed']) assert.equal(rows[key],c[key],`${c.name}: ${key}`);
  const tx=C.FixedTransaction.from_hex(rows.signed);
  assert.equal(hex(tx.raw_body()),c.payload);
  const w=tx.witness_set().vkeys().get(0);
  assert(w.vkey().public_key().verify(tx.transaction_hash().to_bytes(),w.signature()));
}
console.log(`Cardano CSL ${pkg.version}: ${cases.length} signed cases, ${rejected.length} rejection fixtures`);
