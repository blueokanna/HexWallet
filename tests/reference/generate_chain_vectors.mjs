// Independent SDK oracles; only public TEST ONLY seeds are used here.
// Install the pinned packages in build/chain-sdk (see docs/chain-validation.md).
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(path.join(root, 'build/chain-sdk/package.json'));
const { Transaction: SuiTransaction } = require('@mysten/sui/transactions');
const { Ed25519Keypair } = require('@mysten/sui/keypairs/ed25519');
const { TypeRegistry } = require('@polkadot/types');
const pc = require('@polkadot/util-crypto');
const thor = require('thor-devkit');
const fil = await import(pathToFileURL(path.join(root,
  'build/chain-sdk/node_modules/@zondax/filecoin-signing-tools/js/dist/index.js')));
const filUtils = await import(pathToFileURL(path.join(root,
  'build/chain-sdk/node_modules/@zondax/filecoin-signing-tools/js/dist/utils.js')));
const seed = Buffer.from(Array.from({length: 64}, (_, i) => i));
const hex = b => Buffer.from(b).toString('hex');
const le = (v, n) => { const b = Buffer.alloc(n); let x = BigInt(v); for(let i=0;i<n;i++){b[i]=Number(x&255n);x>>=8n;} return b; };
const be = (v, n) => le(v,n).reverse();
const hash = b => Buffer.from(pc.blake2AsU8a(b,256));
const registry = new TypeRegistry();
const compact = v => Buffer.from(registry.createType('Compact<u128>', String(v)).toU8a());
const cat = (...v) => Buffer.concat(v.map(x=>Buffer.from(x)));
const cases = [], rejected = [];
function slip10(coin,index){
  let node = crypto.createHmac('sha512','ed25519 seed').update(seed).digest();
  for(const i of [44,coin,0,0,index]) node = crypto.createHmac('sha512',node.subarray(32)).update(cat([0],node.subarray(0,32),be(BigInt(i)+0x80000000n,4))).digest();
  return node.subarray(0,32);
}
for(const index of [0,1,7]) {
  const key = Ed25519Keypair.deriveKeypairFromSeed(hex(seed),`m/44'/784'/0'/0'/${index}'`);
  const sender = key.toSuiAddress(), recipient = '0x'+'11'.repeat(32);
  const make = async (change={}) => {
    const tx = new SuiTransaction(); tx.setSender(sender);
    tx.setGasOwner(change.gasOwner ?? sender);
    tx.setGasPrice(1000); tx.setGasBudget(change.budget ?? 10000000);
    tx.setGasPayment([{objectId:'0x'+'22'.repeat(32),version:'123',digest:pc.base58Encode(new Uint8Array(32).fill(0x33))}]);
    if(index) tx.setExpiration({Epoch:1234});
    const [coin] = tx.splitCoins(tx.gas,[tx.pure.u64(change.amount ?? 1234567890)]);
    tx.transferObjects([coin],tx.pure.address(recipient));
    if(change.extra) tx.transferObjects([tx.gas],tx.pure.address(recipient));
    return Buffer.from(await tx.build());
  };
  const payload = await make();
  const signed = await key.signTransaction(payload);
  cases.push({name:`sui-${index}`,network:'sui',index,payload:hex(payload),address:sender,recipient,
    amount:'1.23456789 SUI',fee:'0.01 SUI MAX',hash:hex(hash(cat([0,0,0],payload))),signed:hex(Buffer.from(signed.signature,'base64'))});
  for(const [name,change] of [['sponsored',{gasOwner:recipient}],['extra-command',{extra:true}],['zero',{amount:0}],['fee-limit',{budget:100000000001}]])
    rejected.push({name:`sui-${name}-${index}`,network:'sui',index,payload:hex(await make(change))});
}
for(const index of [0,1,7]) {
  const key = fil.keyDeriveFromSeed(seed,`m/44'/461'/0'/0/${index}`);
  const dest = fil.keyRecover(Buffer.alloc(32,0x11),false).address;
  for(const recipient of [dest, 'f01234', fil.encodeAddress(cat([3],Buffer.alloc(48,0x23)),false)]) {
    const message = {To:recipient,From:key.address,Nonce:7,Value:'1234567890123456789',GasLimit:1000000,
      GasFeeCap:'100000',GasPremium:'50000',Method:0,Params:''};
    const payload = fil.transactionSerializeRaw(message), signature = fil.transactionSignRaw(message,key.privateKey);
    cases.push({name:`fil-${index}-${recipient.slice(0,2)}`,network:'fil',index,payload:hex(payload),address:key.address,recipient,
      amount:'1.234567890123456789 FIL',fee:'0.0000001 FIL MAX',hash:hex(filUtils.getDigest(payload)),
      signed:hex(cat([0x82],payload,[0x58,66,1],signature))});
    for(const [name,change] of [['method',{Method:2}],['params',{Params:'AQ=='}],['zero',{Value:'0'}],['premium',{GasPremium:'100001'}],['gas',{GasLimit:10000000001}],['foreign',{From:dest}],['overflow',{Value:String(2n**128n-1n)}]])
      rejected.push({name:`fil-${name}-${index}-${recipient.slice(0,2)}`,network:'fil',index,payload:fil.transactionSerialize({...message,...change})});
  }
}
function dotVector(network,index,amount,nonce,rawSeed){
  const prefix = network==='dot'?0:2;
  const genesis=Buffer.from(network==='dot'?'91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3':'b0a8d493285c2df73290dfb7e61f870f17b41801197a149ca93654499ea3dafe','hex');
  const key = rawSeed ?? slip10(network==='dot'?354:434,index), pair=pc.ed25519PairFromSeed(key);
  const pub=Buffer.from(pair.publicKey), to=Buffer.alloc(32,0x11), versions=cat(le(1005000,4),le(26,4));
  const call=cat([5,3,0],to,compact(amount)), extra=cat([0],compact(nonce),[0]);
  const signing=cat(call,extra,versions,genesis,genesis), signature=pc.ed25519Sign(signing,pair);
  const body=cat([0x84,0],pub,[0],signature,extra,call);
  return {name:`${network}-${index}-${amount}-${nonce}`,network,index,payload:hex(cat(Buffer.from('DOT1'),[prefix,3],to,be(amount,16),le(nonce,4),versions,genesis,genesis)),
    address:pc.encodeAddress(pub,prefix),recipient:pc.encodeAddress(to,prefix),hash:hex(hash(signing)),signed:hex(cat(compact(body.length),body)),signing:hex(signing)};
}
for(const network of ['dot','ksm']) for(const amount of [1n,63n,64n,16383n,16384n,2n**30n-1n,2n**30n,2n**64n,2n**128n-1n])
  cases.push(dotVector(network,1,amount,0x40000000));
const dotSelftest = dotVector('dot',0,1234567890123n,7,Buffer.from(Array.from({length:32},(_,i)=>i)));
for(const network of ['vet','icx']) for(const index of [0,1]) {
  const key = fil.keyDeriveFromSeed(seed,`m/44'/${network==='vet'?818:74}'/0'/0/${index}`).privateKey;
  const pub = thor.secp256k1.derivePublicKey(key,false), to=Buffer.alloc(20,0x11), value=1234567890123456789n;
  if(network==='vet') {
    const tx=new thor.Transaction({chainTag:0x27,blockRef:'0x00000000a1b2c3d4',expiration:720,
      clauses:[{to:'0x'+hex(to),value:'0x'+value.toString(16),data:'0x'}],gasPriceCoef:0,gas:21000,dependsOn:null,nonce:123456789});
    const digest=tx.signingHash(); tx.signature=thor.secp256k1.sign(digest,key);
    cases.push({name:`vet-${index}`,network,index,address:tx.origin,recipient:'0x'+hex(to),hash:hex(digest),signed:hex(tx.encode()),
      amount:'1.234567890123456789 VET',payload:hex(cat(Buffer.from('VET1'),le(0x27,4),Buffer.from('00000000a1b2c3d4','hex'),le(720,4),le(0,4),le(21000,8),[1,20],to,be(value,16),[0,0],le(123456789,8)))});
  } else {
    const sender='hx'+crypto.createHash('sha3-256').update(pub.subarray(1)).digest('hex').slice(-40);
    const timestamp=1700000000000000n, nonce=123456789;
    const serialized=`icx_sendTransaction.from.${sender}.nid.0x1.nonce.0x${nonce.toString(16)}.stepLimit.0x186a0.timestamp.0x${timestamp.toString(16)}.to.hx${hex(to)}.value.0x${value.toString(16)}.version.0x3`;
    const digest=crypto.createHash('sha3-256').update(serialized).digest();
    cases.push({name:`icx-${index}`,network,index,address:sender,recipient:'hx'+hex(to),hash:hex(digest),signed:hex(thor.secp256k1.sign(digest,key)),
      amount:'1.234567890123456789 ICX',payload:hex(cat(Buffer.from('ICX1'),le(1,4),le(nonce,8),le(100000,8),le(timestamp,8),be(value,16),[20],to))});
  }
}
let result={notice:'TEST ONLY: deterministic public seed, no funds. These are offline SDK vectors, not mainnet acceptance evidence.',
  sdk:JSON.parse(fs.readFileSync(path.join(root,'build/chain-sdk/package.json'))).dependencies,seed:hex(seed),cases,rejected,dotSelftest};
const suiFilecoinOnly = process.argv.includes('--sui-filecoin');
if (suiFilecoinOnly) {
  result = {...result, sdk: Object.fromEntries(Object.entries(result.sdk).filter(([name]) =>
    ['@mysten/sui','@zondax/filecoin-signing-tools'].includes(name))),
    cases: cases.filter(c => ['sui','fil'].includes(c.network)),
    rejected: rejected.filter(c => ['sui','fil'].includes(c.network))};
  delete result.dotSelftest;
}
const target=path.join(root,`tests/fixtures/${suiFilecoinOnly ? 'sui-filecoin' : 'chain'}-sdk.json`), text=JSON.stringify(result,null,2)+'\n';
if(process.argv.includes('--check')) {if(fs.readFileSync(target,'utf8')!==text) throw Error('chain SDK fixture drift');}
else fs.writeFileSync(target,text);
console.log(`${result.cases.length} positive and ${result.rejected.length} negative independent SDK vectors`);
