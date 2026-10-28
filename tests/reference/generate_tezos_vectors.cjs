// Desktop-only Taquito 25.0.0 oracle. Public synthetic seed: NEVER use for funds.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const sdk = process.env.HEXWALLET_TEZOS_SDK_DIR || path.join(root, 'build/tezos-sdk');
const load = name => require(path.join(sdk, 'node_modules', name));
for (const name of ['local-forging', 'signer', 'utils']) {
  if (load('@taquito/' + name + '/package.json').version !== '25.0.0') throw Error('Pin Taquito 25.0.0');
}
const {localForger} = load('@taquito/local-forging');
const {InMemorySigner} = load('@taquito/signer');
const {b58Encode, PrefixV2: P} = load('@taquito/utils');
const sdkRequire = require('node:module').createRequire(require.resolve(path.join(sdk,'node_modules/@taquito/signer')));
const {blake2b} = sdkRequire('@noble/hashes/blake2.js');
const seed = Buffer.from(Array.from({length:64}, (_,i)=>i));
const hex = value => Buffer.from(value).toString('hex');
function child(index) {
  let node = crypto.createHmac('sha512', 'ed25519 seed').update(seed).digest();
  for (const component of [44,1729,0,0,index]) {
    const i = Buffer.alloc(4); i.writeUInt32BE(component + 0x80000000);
    node = crypto.createHmac('sha512',node.subarray(32)).update(Buffer.concat([Buffer.from([0]),node.subarray(0,32),i])).digest();
  }
  return node.subarray(0,32);
}
async function make(name, options={}) {
  const index = options.index || 0, secret = child(index);
  const signer = await InMemorySigner.fromSecretKey(b58Encode(secret,P.Ed25519Seed));
  const source = await signer.publicKeyHash(), public_key = await signer.publicKey();
  const pk = crypto.createPublicKey(crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),secret]),format:'der',type:'pkcs8'}));
  const public_raw = pk.export({format:'der',type:'spki'}).subarray(-32);
  if (b58Encode(public_raw,P.Ed25519PublicKey) !== public_key) throw Error('public key mismatch');
  const branch = b58Encode(Buffer.from(Array.from({length:32},(_,i)=>i+1)),P.BlockHash);
  const destination = b58Encode(Buffer.alloc(20,0x11),options.destinationPrefix || P.Ed25519PublicKeyHash);
  const common = {source,fee:'1300',counter:'42',gas_limit:'10600',storage_limit:'257'};
  const transfer = {kind:'transaction',...common,amount:'1234567',destination,...options.transfer};
  const reveal = {kind:'reveal',...common,public_key};
  let contents = [transfer];
  if (options.reveal) contents = [reveal,{...transfer,counter:'43'}];
  if (options.onlyReveal) contents = [reveal];
  if (options.batch) contents = Array.from({length:options.batch},(_,i)=>({...transfer,counter:String(42+i),amount:String(i+1)}));
  if (options.modify) contents = options.modify(contents,reveal,transfer);
  const transaction = await localForger.forge({branch,contents});
  const operation_ends=[];
  for (let i=1; i<=contents.length; ++i) operation_ends.push((await localForger.forge({branch,contents:contents.slice(0,i)})).length/2);
  const signed = await signer.sign(transaction,new Uint8Array([3]));
  const hash = blake2b(Buffer.concat([Buffer.from([3]),Buffer.from(transaction,'hex')]),{dkLen:32});
  const signature = Buffer.from(signed.sbytes.slice(transaction.length),'hex');
  if (!crypto.verify(null,hash,pk,signature)) throw Error('Independent OpenSSL Ed25519 verification failed');
  return {name,index,transaction,signed:signed.sbytes,hash:hex(hash),signer:source,public_key,
    public_raw:hex(public_raw),branch,contents,operation_ends};
}
(async()=>{
  const cases=[];
  for (const [name,options] of [
    ['transfer',{}],['one-mutez',{transfer:{amount:'1'}}],['fraction',{transfer:{amount:'100000'}}],
    ['maximum-amount',{transfer:{amount:String(2n**63n-1n)}}],['index-7',{index:7}],
    ['reveal-and-transfer',{reveal:true}],['reveal',{onlyReveal:true}],['batch-16',{batch:16}],
    ['tz2',{destinationPrefix:P.Secp256k1PublicKeyHash}],['tz3',{destinationPrefix:P.P256PublicKeyHash}],
    ['tz4',{destinationPrefix:P.BLS12_381PublicKeyHash}],['max-counter',{transfer:{counter:String(2n**63n-1n)}}]
  ]) cases.push(await make(name,options));
  const rejected=[];
  for (const [name,options] of [
    ['zero-amount',{transfer:{amount:'0'}}],['zero-counter',{transfer:{counter:'0'}}],
    ['fee-cap',{transfer:{fee:'1000001'}}],['gas-cap',{transfer:{gas_limit:'1040001'}}],
    ['zero-gas',{transfer:{gas_limit:'0'}}],['storage-cap',{transfer:{storage_limit:'60001'}}],
    ['too-many',{batch:17}],['kt1-call',{destinationPrefix:P.ContractHash}],
    ['parameters',{transfer:{parameters:{entrypoint:'transfer',value:{prim:'Unit'}}}}],
    ['foreign-source',{transfer:{source:b58Encode(Buffer.alloc(20,0x33),P.Ed25519PublicKeyHash)}}],
    ['counter-gap',{modify:(_,r,t)=>[t,{...t,counter:'44'}]}],
    ['reveal-after-transfer',{modify:(_,r,t)=>[t,{...r,counter:'43'}]}],
    ['total-overflow',{modify:(_,r,t)=>[{...t,amount:String(2n**63n-1n)},{...t,counter:'43',amount:'1'}]}],
    ['delegation',{modify:(_,r,t)=>[{kind:'delegation',source:t.source,fee:t.fee,counter:t.counter,gas_limit:t.gas_limit,storage_limit:'0',delegate:t.destination}]}]
  ]) rejected.push(await make(name,options));
  const fixture={sdk:'Taquito',version:'25.0.0',seed:hex(seed),
    parameters:'TEST ONLY seed 00..3f; synthetic block/counters; no node acceptance or funds',
    generator_sha256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),cases,rejected};
  const file=path.join(root,'tests/fixtures/tezos-sdk.json'), content=JSON.stringify(fixture,null,2)+'\n';
  if(process.argv.includes('--check')) {if(fs.readFileSync(file,'utf8')!==content) throw Error('Stale Tezos fixture');}
  else fs.writeFileSync(file,content);
})().catch(e=>{console.error(e);process.exitCode=1;});
