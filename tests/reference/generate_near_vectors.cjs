// Offline near-api-js 5.1.1 oracle. Public synthetic keys; never use for funds.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const sdkDir = process.env.HEXWALLET_NEAR_SDK_DIR || path.join(root, 'build/near-sdk');
const sdkPath = path.join(sdkDir, 'node_modules/near-api-js');
const near = require(sdkPath);
if (require(path.join(sdkPath, 'package.json')).version !== '5.1.1') throw Error('Pin near-api-js 5.1.1');
const seed = Buffer.from(Array.from({length:64}, (_,i)=>i));
const sha = data => crypto.createHash('sha256').update(data).digest();
const hex = data => Buffer.from(data).toString('hex');
function keypair(index) {
  let node = crypto.createHmac('sha512', Buffer.from('ed25519 seed')).update(seed).digest();
  for (const component of [44,397,index]) {
    const child = Buffer.alloc(4); child.writeUInt32BE(component + 0x80000000);
    node = crypto.createHmac('sha512',node.subarray(32)).update(Buffer.concat([Buffer.from([0]),node.subarray(0,32),child])).digest();
  }
  return near.KeyPair.fromString('ed25519:'+near.utils.serialize.base_encode(node.subarray(0,32)));
}
function make(name, options={}) {
  const index=options.index || 0, key=keypair(index), pk=key.getPublicKey();
  const implicit=hex(pk.data), signer=options.signer || implicit, receiver=options.receiver || 'receiver.near';
  const amounts=options.amounts || [1234567890123456789012345n];
  const actions=options.actions || amounts.map(n=>near.transactions.transfer(n));
  const blockHash=options.blockHash || Buffer.from(Array.from({length:32},(_,i)=>i+1));
  const tx=near.transactions.createTransaction(signer,pk,receiver,options.nonce ?? 42n,actions,blockHash);
  const raw=near.transactions.encodeTransaction(tx), hash=sha(raw), signed=key.sign(hash);
  if (!key.verify(hash,signed.signature)) throw Error('Independent signature verification failed');
  const envelope=new near.transactions.SignedTransaction({transaction:tx,
    signature:new near.transactions.Signature({keyType:pk.keyType,data:signed.signature})});
  const total=amounts.reduce((a,b)=>a+b,0n);
  return {name,index,transaction:hex(raw),signed:hex(envelope.encode()),hash:hex(hash),
    implicit,signer,receiver,public_key:pk.toString(),block_hash:near.utils.serialize.base_encode(blockHash),
    nonce:String(options.nonce ?? 42n),amounts:amounts.map(String),total:String(total),
    formatted:`${total/10n**24n}.${String(total%10n**24n).padStart(24,'0')} NEAR`};
}
const cases=[make('implicit'),make('named',{signer:'alice.near'}),make('one-yocto',{amounts:[1n]}),
  make('one-near',{amounts:[10n**24n]}),make('u128-max',{amounts:[2n**128n-1n]}),
  make('different-key',{index:3}),make('batch',{amounts:[1n,2n,10n**24n]}),
  make('max-actions',{amounts:Array(16).fill(1n)}),
  make('u64-nonce',{nonce:2n**64n-1n}),make('implicit-recipient',{receiver:'12'.repeat(32)}),
  make('subaccount',{signer:'sub.alice.near',receiver:'some-id.valid_name.near'})];
const rejected=[make('zero',{amounts:[0n]}),make('overflow',{amounts:[2n**128n-1n,1n]}),
  make('zero-nonce',{nonce:0n}),make('zero-block',{blockHash:Buffer.alloc(32)}),
  make('too-many',{amounts:Array(17).fill(1n)}),make('foreign-implicit',{signer:'00'.repeat(32)}),
  make('delete-account',{actions:[near.transactions.deleteAccount('receiver.near')]}),
  make('function-call',{actions:[near.transactions.functionCall('nft_transfer',{receiver_id:'receiver.near',token_id:'1'},10000000000000n,1n)]}),
  ...['A.near','a..near','a._near','.abc','abc.','a','x'.repeat(65),'a\0.near'].map((receiver,i)=>make('invalid-account-'+i,{receiver}))];
const fixture={sdk:'near-api-js',version:'5.1.1',seed:hex(seed),
  parameters:'TEST ONLY: synthetic keys, block hash and nonces; no RPC, broadcast or funds',
  generator_sha256:hex(sha(fs.readFileSync(__filename))),cases,rejected};
const output=path.join(root,'tests/fixtures/near-sdk.json'), content=JSON.stringify(fixture,null,2)+'\n';
if (process.argv.includes('--check')) {
  if (fs.readFileSync(output,'utf8')!==content) throw Error('NEAR SDK fixture is stale');
} else fs.writeFileSync(output,content);
