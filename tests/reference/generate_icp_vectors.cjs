// Independent ICP SDK oracle; public test seed, no RPC or real keys.
const fs=require('node:fs'),path=require('node:path'),url=require('node:url'),crypto=require('node:crypto');
const assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'../..');
const base=path.join(root,'build/icp-sdk/node_modules/@icp-sdk/core/lib/cjs');
const {IDL}=require(path.join(base,'candid/index.js'));
const {Principal}=require(path.join(base,'principal/index.js'));
const {Ed25519KeyIdentity}=require(path.join(base,'identity/index.js'));
const {requestIdOf}=require(path.join(base,'agent/request_id.js'));
const {Cbor}=require(path.join(base,'agent/cbor.js'));
const hex=x=>Buffer.from(x).toString('hex'),cat=(...x)=>Buffer.concat(x.map(v=>Buffer.from(v)));
const le=(x,n=8)=>{const b=Buffer.alloc(n);let v=BigInt(x);for(let i=0;i<n;i++){b[i]=Number(v&255n);v>>=8n;}return b;};
const seed=Buffer.from(Array.from({length:64},(_,i)=>i));
function child(index){let h=crypto.createHmac('sha512','ed25519 seed').update(seed).digest();for(const i of [44,223,0,0,index])h=crypto.createHmac('sha512',h.subarray(32)).update(cat([0],h.subarray(0,32),le(i+0x80000000,4).reverse())).digest();return h.subarray(0,32);}
async function main(){
 const store=path.join(root,'build/icp-sdk/node_modules/.pnpm');
 const direct=path.join(root,'build/icp-sdk/node_modules/@icp-sdk/canisters');
 const canisterRoot=fs.existsSync(direct) ? direct : path.join(store,fs.readdirSync(store).find(x=>x.startsWith('@icp-sdk+canisters@4.0.0_')),'node_modules/@icp-sdk/canisters');
 const {AccountIdentifier}=await import(url.pathToFileURL(path.join(canisterRoot,'ledger/icp/index.js')));
 const {idlFactory}=await import(url.pathToFileURL(path.join(canisterRoot,'declarations/ledger-icp/ledger.idl.js')));
 const argType=idlFactory({IDL})._fields.find(x=>x[0]==='transfer')[1].argTypes[0];
 const cases=[],rejected=[];
 const to=AccountIdentifier.fromPrincipal({principal:Ed25519KeyIdentity.fromSecretKey(new Uint8Array(32).fill(17)).getPrincipal()}).toUint8Array();
 for(const index of [0,1,17])for(const memo of [0n,18446744073709551615n]){
  const key=Ed25519KeyIdentity.fromSecretKey(child(index));
  const amount=123456789n,fee=10000n,created=1793000000000000000n,expiry=created+120000000000n;
  const value={to,fee:{e8s:fee},memo,from_subaccount:[],created_at_time:[{timestamp_nanos:created}],amount:{e8s:amount}};
  const arg=IDL.encode([argType],[value]);
  const content={request_type:'call',canister_id:Principal.fromText('ryjl3-tyaaa-aaaaa-aaaba-cai').toUint8Array(),method_name:'transfer',arg,sender:key.getPrincipal().toUint8Array(),ingress_expiry:expiry};
  const hash=requestIdOf(content),signature=await key.sign(cat([10],Buffer.from('ic-request'),hash));
  const payload=cat(Buffer.from('ICP1'),to,le(amount),le(fee),le(memo),le(created),le(expiry));
  const c={name:`icp-${index}-${memo}`,network:'icp',index,seed:hex(seed),payload:hex(payload),address:AccountIdentifier.fromPrincipal({principal:key.getPrincipal()}).toHex(),recipient:hex(to),amount:'1.23456789 ICP',fee:'0.0001 ICP',hash:hex(hash),signature:hex(signature),arg:hex(arg),public_der:hex(key.getPublicKey().toDer()),principal:hex(key.getPrincipal().toUint8Array())};
  cases.push(c);
  if(process.argv.includes('--verify-device')){
   const p=spawnSync(path.join(root,'build/chain-native/Release/chain_probe.exe'),['icp',c.seed,c.payload,String(index)],{encoding:'utf8'});assert.equal(p.status,0,p.stdout+p.stderr);
   const actual=Object.fromEntries(p.stdout.trim().split(/\r?\n/).map(x=>x.split('=')));
   for(const k of ['address','recipient','amount','fee','hash'])assert.equal(actual[k],c[k],c.name+':'+k);
   const decoded=Cbor.decode(Buffer.from(actual.signed,'hex'));
   assert.equal(hex(decoded.sender_sig),c.signature);assert.equal(hex(decoded.sender_pubkey),c.public_der);
   assert.equal(hex(decoded.content.arg),c.arg);assert.equal(hex(requestIdOf(decoded.content)),c.hash);
   assert.equal(decoded.content.method_name,'transfer');
   assert.deepEqual(IDL.decode([argType],Uint8Array.from(decoded.content.arg)),IDL.decode([argType],Uint8Array.from(arg)));
  }
 }
 const c=cases[0],raw=Buffer.from(c.payload,'hex');
 for(const [name,offset] of [['bad-address-checksum',4],['bad-fee',44],['bad-magic',0]]){const b=Buffer.from(raw);b[offset]^=1;rejected.push({...c,name,payload:hex(b)});}
 for(const [name,offset] of [['zero-amount',36],['zero-created',60],['zero-expiry',68]]){const b=Buffer.from(raw);b.fill(0,offset,offset+8);rejected.push({...c,name,payload:hex(b)});}
 const data={test_only:true,source:'@icp-sdk/core 6.1.1 and @icp-sdk/canisters 4.0.0 ledger.idl.js',cases,rejected};
 const target=path.join(root,'tests/fixtures/icp-sdk.json');
 if(process.argv.includes('--check'))assert.deepEqual(JSON.parse(fs.readFileSync(target)),data);else fs.writeFileSync(target,JSON.stringify(data,null,2)+'\n');
 console.log(`ICP SDK: ${cases.length} cases; ${rejected.length} rejection fixtures`);
}
main().catch(e=>{console.error(e);process.exitCode=1;});
