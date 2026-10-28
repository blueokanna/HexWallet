// Public test seed only. Independent pinned SDK serialization/signature oracles.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'../..');
const nem=require(path.join(root,'build/nem-sdk/node_modules/nem-sdk')).default;
const hive=require(path.join(root,'build/nem-sdk/node_modules/@hiveio/dhive'));
const {HDKey}=require(path.join(root,'build/flow-sdk/node_modules/@scure/bip32'));
const hex=b=>Buffer.from(b).toString('hex');
const seed=Buffer.from(Array.from({length:64},(_,i)=>i));
const cat=(...v)=>Buffer.concat(v.map(x=>Buffer.from(x)));
const le=(x,n)=>{const b=Buffer.alloc(n);let v=BigInt(x);for(let i=0;i<n;i++){b[i]=Number(v&255n);v>>=8n;}return b;};
function slip(coin,index){let h=crypto.createHmac('sha512','ed25519 seed').update(seed).digest();for(const i of [44,coin,0,0,index])h=crypto.createHmac('sha512',h.subarray(32)).update(cat([0],h.subarray(0,32),le(i+0x80000000,4).reverse())).digest();return h.subarray(0,32);}
const edPublic=sk=>crypto.createPublicKey(crypto.createPrivateKey({key:cat(Buffer.from('302e020100300506032b657004220420','hex'),sk),format:'der',type:'pkcs8'})).export({format:'der',type:'spki'}).subarray(-32);
const cases=[],rejected=[];
function add(c){cases.push({seed:hex(seed),...c});}
function bad(c,name,payload){rejected.push({...c,name,payload:hex(payload)});}
async function main(){
for(const index of [0,1,17])for(const memo of ['', 'invoice 42']){
 const sk=slip(43,index),key=nem.crypto.keyPair.create(hex(Buffer.from(sk).reverse()));
 const pk=key.publicKey.toString(),address=nem.model.address.toAddress(pk,104);
 const to=nem.model.address.toAddress(nem.crypto.keyPair.create('11'.repeat(32)).publicKey.toString(),104);
 const tx={type:257,version:0x68000001,timeStamp:360000000,signer:pk,fee:50000,deadline:360003600,recipient:to,amount:1234567,message:{type:1,payload:hex(Buffer.from(memo))}};
 const raw=Buffer.from(nem.utils.serialization.serializeTransaction(tx));
 const sig=key.sign(raw).toString();assert(require(path.join(root,'build/nem-sdk/node_modules/nem-sdk/build/crypto/keyPair')).verifySignature(pk,hex(raw),sig));
 add({name:`nem-${index}-${memo?'memo':'empty'}`,network:'xem',index,payload:hex(raw),address,recipient:to,amount:'1.234567 XEM',fee:'0.05 XEM',signed:sig,public:pk});
}
const nemCase=cases[0],np=Buffer.from(nemCase.payload,'hex');
for(const [name,offset,value]of [['wrong-network',7,0x98],['mosaic-version',4,2],['wrong-signer',16,np[16]^1],['wrong-checksum',70,65],['other-operation',0,2]]){const b=Buffer.from(np);b[offset]=value;bad(nemCase,name,b);}
for(const index of [0,1,17])for(const amount of ['1.234 HIVE','0.001 HBD']){
 const privateKey=HDKey.fromMasterSeed(seed).derive(`m/44'/3054'/0'/0/${index}`).privateKey;
 const key=hive.PrivateKey.from(Buffer.from(privateKey));
 const tx={ref_block_num:4660,ref_block_prefix:2309737967,expiration:'2026-10-26T04:53:20',operations:[['transfer',{from:'test-account-1',to:'hiveio',amount,memo:'hello'}]],extensions:[]};
 const str=x=>cat([Buffer.byteLength(x)],Buffer.from(x));
 const raw=cat(Buffer.from('HIV1'),le(tx.ref_block_num,2),le(tx.ref_block_prefix,4),le(Date.parse(tx.expiration+'Z')/1000,4),str('test-account-1'),str('hiveio'),str(amount),str('hello'));
 const digest=hive.cryptoUtils.transactionDigest(tx),signed=key.sign(digest);
 assert(key.createPublic().verify(digest,signed));
 add({name:`hive-${index}-${amount.split(' ')[1]}`,network:'hive',index,payload:hex(raw),address:key.createPublic().toString(),recipient:'hiveio',amount,fee:'0 HIVE (resource credits required)',hash:hex(digest),sdk_signature:signed.toString()});
}
const hc=cases.find(c=>c.network==='hive'),hp=Buffer.from(hc.payload,'hex');
for(const [name,offset,value]of [['from-digit',15,49],['memo-control',hp.length-1,10],['memo-null',hp.length-1,0],['encrypted-memo',hp.length-5,35]]){const b=Buffer.from(hp);b[offset]=value;bad(hc,name,b);}
// Sia Foundation's Go SDK/WASM is the independent consensus implementation.
if(!globalThis.crypto)globalThis.crypto=crypto.webcrypto;
require(path.join(root,'build/sia-sdk/package/libs/sdk/src/utils/wasm_exec.cjs.js'));
const wasm=require(path.join(root,'build/sia-sdk/package/libs/sdk/src/resources/sdk.wasm.cjs.js'));
const go=new globalThis.Go();const inst=await wasm(go.importObject);void go.run(inst.instance);
const sia=globalThis.sia.wallet;
for(const index of [0,1,17])for(const count of [1,2]){
 const sk=slip(1991,index),pk=edPublic(sk),policy={type:'pk',policy:'ed25519:'+hex(pk)};
 const address=sia.addressFromSpendPolicy(policy).address;assert(address);
 const recipient=sia.addressFromSpendPolicy({type:'pk',policy:'ed25519:'+'11'.repeat(32)}).address;
 const amount=1234567890123456789012345n,fee=10000000000000000000000n,change=count===2?2000000000000000000000000n:0n;
 const input=amount+fee+change,id='22'.repeat(32);
 const outputs=[{value:String(amount),address:recipient}];if(count===2)outputs.push({value:String(change),address});
 const tx={siacoinInputs:[{parent:{id,siacoinOutput:{value:String(input),address},maturityHeight:0,stateElement:{leafIndex:0,merkleProof:[]}},satisfiedPolicy:{policy,signatures:[],preimages:[]}}],siacoinOutputs:outputs,minerFee:String(fee)};
 const hashResult=sia.v2TransactionInputSigHash({}, {},tx);assert(!hashResult.error,JSON.stringify(hashResult));
 const sigResult=sia.signHash(hex(cat(sk,pk)),hashResult.sigHash);assert(!sigResult.error,JSON.stringify(sigResult));
 const payload=cat(Buffer.from('SCV2'),Buffer.from(id,'hex'),le(input,16),Buffer.from(address.slice(0,64),'hex'),[count],...outputs.map(o=>cat(le(o.value,16),Buffer.from(o.address.slice(0,64),'hex'))),le(fee,16));
 add({name:`sia-${index}-${count}`,network:'sc',index,address,recipient,amount:'1.234567890123456789012345 SC',fee:'0.01 SC',hash:hashResult.sigHash,signed:sigResult.signature,payload:hex(payload)});
}
const sc=cases.find(c=>c.network==='sc'),sp=Buffer.from(sc.payload,'hex');
for(const [name,offset]of [['wrong-parent-owner',52],['bad-balance',36],['bad-output-count',84],['wrong-magic',3]]){const b=Buffer.from(sp);b[offset]^=1;bad(sc,name,b);}
const data={test_only:true,sources:{nem:'nem-sdk 1.6.11',hive:'@hiveio/dhive 1.3.6',sia:'@siafoundation/sdk 0.5.0'},cases,rejected};
const dest=path.join(root,'tests/fixtures/native-remaining-sdk.json');
if(process.argv.includes('--check'))assert.deepEqual(JSON.parse(fs.readFileSync(dest)),data);else fs.writeFileSync(dest,JSON.stringify(data,null,2)+'\n');
if(process.argv.includes('--verify-device'))for(const c of cases){
 const p=spawnSync(path.join(root,'build/chain-native/Release/chain_probe.exe'),[c.network,c.seed,c.payload,String(c.index)],{encoding:'utf8'});assert.equal(p.status,0,p.stdout+p.stderr);
 const actual=Object.fromEntries(p.stdout.trim().split(/\r?\n/).map(x=>x.split('=')));
 for(const k of ['address','recipient','amount','fee','hash','signed'])if(c[k])assert.equal(actual[k],c[k],c.name+':'+k);
 if(c.network==='hive'){
  const sig=hive.Signature.fromString(actual.signed),pk=hive.PublicKey.fromString(c.address),digest=Buffer.from(c.hash,'hex');
  assert(hive.cryptoUtils.isCanonicalSignature(sig.data));assert(pk.verify(digest,sig));assert.equal(sig.recover(digest).toString(),c.address);
 }
}
console.log(`${cases.length} independent native-chain cases; ${rejected.length} negative cases`);
process.exit(0);
}
main().catch(e=>{console.error(e);process.exit(1);});
