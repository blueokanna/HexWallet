// PUBLIC TEST mnemonic only; Hedera SDK provides derivation, protobuf, signing.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const assert=require('node:assert/strict');
const {createRequire}=require('node:module'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'../..');
const sdkPath=path.join(root,'build/hedera-sdk/node_modules/@hashgraph/sdk');
const S=require(sdkPath),requireSdk=createRequire(require.resolve(sdkPath));
const {proto:P}=requireSdk('@hashgraph/proto');
const Long=requireSdk('long');
assert.equal(require(path.join(sdkPath,'package.json')).version,'2.70.0');
const hex=x=>Buffer.from(x).toString('hex');
const mnemonic='abandon '.repeat(11)+'about';
const seed=crypto.pbkdf2Sync(mnemonic,'mnemonic',2048,64,'sha512');
const enc=(type,value)=>Buffer.from(type.encode(value).finish());
const cases=[],rejected=[];
(async()=>{
for(const index of [0,1,17]) for(const memo of ['', 'invoice 42']) {
  const key=await (await S.Mnemonic.fromString(mnemonic)).toStandardEd25519PrivateKey('',index);
  const tx=new S.TransferTransaction()
    .setTransactionId(S.TransactionId.fromString('0.0.1001@1700000000.123456789'))
    .setNodeAccountIds([S.AccountId.fromString('0.0.3')])
    .setMaxTransactionFee(S.Hbar.fromTinybars(1000000))
    .setTransactionValidDuration(120).setTransactionMemo(memo)
    .addHbarTransfer('0.0.1001',S.Hbar.fromTinybars(-123456789))
    .addHbarTransfer('0.0.2002',S.Hbar.fromTinybars(123456789)).freeze();
  await tx.sign(key);
  const list=P.TransactionList.decode(tx.toBytes());
  assert.equal(list.transactionList.length,1);
  const full=list.transactionList[0];
  const signed=P.SignedTransaction.decode(full.signedTransactionBytes);
  assert.equal(signed.sigMap.sigPair.length,1);
  assert(key.publicKey.verify(signed.bodyBytes,signed.sigMap.sigPair[0].ed25519));
  const c={name:`index${index}-${memo?'memo':'empty'}`,network:'hbar',seed:hex(seed),index,
    payload:hex(signed.bodyBytes),address:key.publicKey.toAccountId(0,0).toString(),
    recipient:'0.0.2002',amount:'1.23456789 HBAR',fee:'MAX 0.01 HBAR',
    hash:crypto.createHash('sha256').update(signed.bodyBytes).digest('hex'),
    signed:hex(enc(P.Transaction,full)),public:key.publicKey.toStringRaw()};
  cases.push(c);
}
const baseline=cases[0];
function bad(name,mutate){
  const b=P.TransactionBody.decode(Buffer.from(baseline.payload,'hex'));
  mutate(b);
  rejected.push({name,network:'hbar',seed:hex(seed),index:0,payload:hex(enc(P.TransactionBody,b))});
}
bad('allowance',b=>b.cryptoTransfer.transfers.accountAmounts[0].isApproval=true);
bad('unbalanced',b=>b.cryptoTransfer.transfers.accountAmounts[1].amount=Long.fromNumber(123456788));
bad('wrong-payer',b=>b.transactionID.accountID.accountNum=Long.fromNumber(1002));
bad('multiple-recipients',b=>b.cryptoTransfer.transfers.accountAmounts.push(b.cryptoTransfer.transfers.accountAmounts[1]));
bad('negative-nanos',b=>b.transactionID.transactionValidStart.nanos=-1);
bad('large-nanos',b=>b.transactionID.transactionValidStart.nanos=1000000000);
bad('scheduled',b=>b.transactionID.scheduled=true);
bad('nonce',b=>b.transactionID.nonce=1);
bad('large-duration',b=>b.transactionValidDuration.seconds=Long.fromNumber(121));
bad('large-fee',b=>b.transactionFee=Long.fromString('10000000001'));
bad('memo-control',b=>b.memo='pay\nAPPROVED');
bad('memo-long',b=>b.memo='x'.repeat(41));
bad('wrong-shard',b=>b.nodeAccountID.shardNum=Long.ONE);
bad('token-transfer',b=>b.cryptoTransfer.tokenTransfers=[{token:{tokenNum:Long.ONE},transfers:[]}]);
bad('zero-amount',b=>b.cryptoTransfer.transfers.accountAmounts[1].amount=Long.ZERO);
for(const [name,payload] of [
  ['duplicate-fee',baseline.payload+'188084af5f'],
  ['trailing-field',baseline.payload+'a00601'],
  ['nonminimal-varint','8a00'+baseline.payload.slice(2)],
]) rejected.push({name,network:'hbar',seed:hex(seed),index:0,payload});
const result={source:'hashgraph/hedera-sdk-js',version:'2.70.0',test_only:true,cases,rejected};
const dest=path.join(root,'tests/fixtures/hedera-sdk.json');
if(process.argv.includes('--check')) assert.deepEqual(JSON.parse(fs.readFileSync(dest)),result);
else fs.writeFileSync(dest,JSON.stringify(result,null,2)+'\n');
if(process.argv.includes('--verify-device'))for(const c of cases){
 const p=spawnSync(path.join(root,'build/chain-native/Release/chain_probe.exe'),
   ['hbar',c.seed,c.payload,String(c.index)],{encoding:'utf8'});
 assert.equal(p.status,0,p.stdout+p.stderr);
 const rows=Object.fromEntries(p.stdout.trim().split(/\r?\n/).map(x=>x.split('=')));
 for(const k of ['address','recipient','amount','fee','hash','signed'])assert.equal(rows[k],c[k],`${c.name}:${k}`);
 const signed=P.SignedTransaction.decode(P.Transaction.decode(Buffer.from(rows.signed,'hex')).signedTransactionBytes);
 assert.equal(hex(signed.bodyBytes),c.payload);
 assert(S.PublicKey.fromStringED25519(c.public).verify(signed.bodyBytes,signed.sigMap.sigPair[0].ed25519));
 assert(S.Transaction.fromBytes(Buffer.from(rows.signed,'hex')) instanceof S.TransferTransaction);
}
console.log(`Hedera SDK 2.70.0: ${cases.length} signed cases, ${rejected.length} rejection fixtures`);
})().catch(e=>{console.error(e);process.exitCode=1;});
