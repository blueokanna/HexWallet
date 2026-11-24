// Install the independent SDKs with npm ci --prefix tests/host/protocol-oracles --ignore-scripts
// and set NODE_PATH to that directory's node_modules. Install the adapter separately
// with npm ci --prefix tools --ignore-scripts. Pass the built chain_probe path as argv[2].
// Only local, deterministic test keys are used. No RPC connection is required.
const assert = require('node:assert/strict');
const {execFileSync, spawnSync} = require('node:child_process');
const {createHash, createHmac} = require('node:crypto');
const path = require('node:path');
const {getBytes, HDNodeWallet, Interface, Mnemonic, Transaction} = require('ethers');
const {DirectSecp256k1Wallet, encodePubkey, makeAuthInfoBytes, makeSignDoc} = require('@cosmjs/proto-signing');
const {TxBody, TxRaw} = require('cosmjs-types/cosmos/tx/v1beta1/tx');
const {MsgSend} = require('cosmjs-types/cosmos/bank/v1beta1/tx');
const {MsgTransfer} = require('cosmjs-types/ibc/applications/transfer/v1/tx');
const {buildIbcTransfer, buildAminoSend, buildRevokeSend, buildGrantSend, broadcastCosmos} = require('../../tools/cosmos_payment.cjs');
const {Secp256k1Wallet, makeSignDoc: makeAminoDoc} = require('@cosmjs/amino');
const {MsgGrant, MsgRevoke} = require('cosmjs-types/cosmos/authz/v1beta1/tx');
const {SendAuthorization} = require('cosmjs-types/cosmos/bank/v1beta1/authz');
const {appendTransactionMessageInstructions, compileTransaction, createKeyPairSignerFromPrivateKeyBytes,
  createTransactionMessage, getTransactionEncoder, pipe, setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash, signTransactionMessageWithSigners} = require('@solana/kit');
const {getSetComputeUnitLimitInstruction} = require('@solana-program/compute-budget');
const {getDeactivateInstruction, getDelegateStakeInstruction} = require('@solana-program/stake');
const {getTransferCheckedInstruction} = require('@solana-program/token');
const legacy = require('./protocol-oracles/legacy-instructions.json');
const {broadcastEthereum, broadcastSolana} = require('../../tools/phone_broadcast.cjs');
const bs58 = require('bs58');

const probe = process.argv[2] || 'build/chain-native/Release/chain_probe.exe';
const seed = Buffer.from(getBytes(Mnemonic.fromPhrase('abandon '.repeat(11) + 'about').computeSeed()));
const index = 3;
const argsFor = (network, bytes) => [network, seed.toString('hex'), bytes, String(index)];
const run = args => execFileSync(probe, args, {encoding: 'utf8'}).replaceAll('\r', '');
const phone = (network, wire, decision = 'approve') => run(['phone-review', network, wire, decision]);
function reject(args) {
  const result = spawnSync(probe, args);
  assert.ifError(result.error);
  assert.equal(result.status, 1);
}

async function evmCatalog() {
  const catalog = process.argv[3] || path.join(__dirname, 'catalog_dump.exe');
  const rows = execFileSync(catalog, ['--native'], {encoding: 'utf8'}).trim().split(/\r?\n/)
    .map(line => line.split('|')).filter(fields => fields[5].startsWith('evm:'));
  assert.ok(rows.length > 0);
  let signedCount = 0;
  const to = '0x1111111111111111111111111111111111111111';
  for (const [id, symbol, , caps, , domain, scope] of rows) {
    assert.ok(Number(caps) & 4, id);
    const chainId = Number(domain.slice(4));
    const coin = {etc: 61, cfx: 503}[id] ?? 60;
    const hdPath = `m/44'/${coin}'/0'/0/${index}`;
    const wallet = HDNodeWallet.fromSeed(seed).derivePath(hdPath);
    const types = [];
    for (const type of [0, 1, 2]) {
      const supported = type === 0 || scope.includes(type === 1 ? 'EIP-2930' : 'EIP-1559');
      const fees = type === 2 ? {maxFeePerGas: 2000000000n, maxPriorityFeePerGas: 100000000n} : {gasPrice: 2000000000n};
      const tx = {type, chainId, nonce: 3, gasLimit: 21000n, value: 125000000000000000n, to, ...fees};
      const unsigned = Transaction.from(tx).unsignedSerialized.slice(2);
      if (!supported) {
        reject(['phone-review', id, unsigned, 'approve']);
        continue;
      }
      const fields = phone(id, unsigned).split('\n');
      for (const field of [`path=${hdPath}`, `address=${wallet.address.toLowerCase()}`, `CHAIN ID ${chainId}`, to,
        `0.125 ${symbol}`, `0.000042 ${symbol}`, `signed=${(await wallet.signTransaction(tx)).slice(2)}`])
        assert.ok(fields.includes(field), `${id} type ${type} missing ${field}`);
      ++signedCount;
      types.push(type);
      if (type === 0) {
        const foreign = Transaction.from({...tx, chainId: chainId === 1 ? 56 : 1});
        reject(['phone-review', id, foreign.unsignedSerialized.slice(2), 'approve']);
      }
    }
    console.log(`${id} chain=${chainId} path=${hdPath} ethers-matched-types=${types.join(',')}`);
  }
  console.log(`EVM catalog: ${rows.length} profiles, ${signedCount} native transfer signatures matched ethers`);
}

async function ethereum() {
  const wallet = HDNodeWallet.fromSeed(seed).derivePath(`m/44'/60'/0'/0/${index}`);
  const lido = '0xae7ab96520de3a18e5e111b5eaab095312d7fe84';
  const router = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d';
  const path = ['0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'];
  const iface = new Interface(['function submit(address)', 'function swapExactETHForTokens(uint256,address[],address,uint256)']);
  const referral = '0x1111111111111111111111111111111111111111';
  for (const [to, data, expected] of [
    [lido, iface.encodeFunctionData('submit', [referral]), ['LIDO STAKE ETH', `REFERRAL\n${referral}`]],
    [router, iface.encodeFunctionData('swapExactETHForTokens', [123456n, path, wallet.address, 1900000000]),
      ['UNISWAP V2 SWAP ETH', 'MINIMUM OUTPUT (raw units) 123456', 'DEADLINE (Unix seconds) 1900000000', path.join('\n'),
       `OUTPUT RECIPIENT\n${wallet.address.toLowerCase()}`]],
  ]) {
    const tx = {type: 2, chainId: 1, nonce: 5, gasLimit: 200000n, maxFeePerGas: 2000000000n,
      maxPriorityFeePerGas: 100000000n, value: 1000000000000000000n, to, data};
    const wire = overrides => Transaction.from({...tx, ...overrides}).unsignedSerialized.slice(2);
    const args = argsFor('eth', wire());
    const result = phone('eth', wire());
    for (const text of [...expected, `address=${wallet.address.toLowerCase()}`, 'INPUT 1 ETH',
      `signed=${(await wallet.signTransaction(tx)).slice(2)}`]) assert.ok(result.includes(text), text);
    const signed = '0x' + /^signed=([a-f0-9]+)$/m.exec(result)[1];
    const id = Transaction.from(signed).hash;
    const rpc = async (method, params) => {
      if (method === 'eth_chainId') return '0x1';
      assert.equal(method, 'eth_sendRawTransaction');
      assert.deepEqual(params, [signed]);
      return id;
    };
    const submit = {rpc, signed, unsigned: '0x' + wire(), chainId: 1, sender: wallet.address};
    assert.equal(await broadcastEthereum(submit), id);
    await assert.rejects(broadcastEthereum({...submit, sender: referral}), /sender/);
    await assert.rejects(broadcastEthereum({...submit, rpc: async () => '0x38'}), /RPC chain mismatch/);
    reject(argsFor('eth', Transaction.from({...tx, data: data + '00'}).unsignedSerialized.slice(2)));
    for (const mode of ['reject', 'cancel', 'expire', 'stale-page', 'low-battery', 'field-lost'])
      assert.ok(!phone('eth', wire(), mode).includes('signed='));
    for (const changes of [{chainId: 56}, {value: 0n}, {data: data.slice(0,-2)}])
      reject(argsFor('eth', wire(changes)));
    for (const [bytes, reason] of [[wire({chainId: 56}), 'Chain ID differs from the selected network.'],
      [wire({gasLimit: 1n}), 'Fee is outside the device limits.'], ['02c0', 'Cannot validate the transaction encoding or fields.']])
      assert.ok(phone('eth', bytes, 'refusal').includes(`refusal=${reason}`));
    reject([...args, 'protocol']);
    const foreign = phone('eth', wire({to: referral}));
    assert.ok(foreign.includes('UNDECODED CONTRACT CALL') && !foreign.includes(expected[0]));
    if (to === router) {
      const swap = (min, route) => iface.encodeFunctionData('swapExactETHForTokens', [min, route, wallet.address, 1900000000]);
      assert.ok(phone('eth', wire({data: swap(0, path)})).includes('NO MINIMUM OUTPUT PROTECTION'));
      for (const invalid of [swap(1, [path[0]]), swap(1, [...path].reverse()),
        swap(1, [path[0], '0x' + '00'.repeat(20)]), data.slice(0, 136) + '60' + data.slice(138)])
        reject(argsFor('eth', wire({data: invalid})));
    }
  }
  const tokenId = (1n << 160n) + 42n;
  const iface721 = new Interface(['function safeTransferFrom(address,address,uint256)']);
  const nft = {type: 2, chainId: 1, nonce: 6, gasLimit: 100000n, maxFeePerGas: 2000000000n,
    maxPriorityFeePerGas: 100000000n, to: '0x57f1887a8bf19b14fc0df6fd9b2acc9af147ea85',
    data: iface721.encodeFunctionData('safeTransferFrom', [wallet.address, referral, tokenId])};
  const nftReview = phone('eth', Transaction.from(nft).unsignedSerialized.slice(2));
  const foreignNft = {...nft, data: iface721.encodeFunctionData('safeTransferFrom', [referral, wallet.address, tokenId])};
  assert.ok(phone('eth', Transaction.from(foreignNft).unsignedSerialized.slice(2), 'refusal')
    .includes('refusal=Transaction ownership check failed.'));
  for (const text of ['ERC-721', tokenId.toString(), referral, `signed=${(await wallet.signTransaction(nft)).slice(2)}`])
    assert.ok(nftReview.includes(text), text);
}

async function solana() {
  const hmac = (key, data) => createHmac('sha512', key).update(data).digest();
  let node = hmac('ed25519 seed', seed);
  for (const segment of [44, 501, 0, 0, index]) {
    const input = Buffer.alloc(37);
    node.copy(input, 1, 0, 32);
    input.writeUInt32BE(0x80000000 + segment, 33);
    node = hmac(node.subarray(32), input);
  }
  const payer = await createKeyPairSignerFromPrivateKeyBytes(node.subarray(0, 32));
  const keys = await Promise.all(Array.from({length: 12}, async (_, i) =>
    (await createKeyPairSignerFromPrivateKeyBytes(Buffer.alloc(32, i + 1))).address));
  const stake = {stake: keys[0], stakeAuthority: payer, vote: keys[1]};
  const saved = ix => ({...ix, data: Buffer.from(ix.data, 'hex')});
  const sdkSwap = saved(legacy.swap);
  // Deployed classic processors take one token program after the fee account.
  const classicSwap = {...sdkSwap, accounts: [...sdkSwap.accounts.slice(0, 9), sdkSwap.accounts[11]]};
  const orca = '9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP';
  function message(ix, v0) {
    return pipe(createTransactionMessage({version: v0 ? 0 : 'legacy'}),
      m => setTransactionMessageFeePayerSigner(payer, m),
      m => setTransactionMessageLifetimeUsingBlockhash({blockhash: keys[11], lastValidBlockHeight: 99n}, m),
      m => appendTransactionMessageInstructions([getSetComputeUnitLimitInstruction({units: 400000}), ix], m));
  }
  const delegated = [`STAKE ACCOUNT\n${keys[0]}`, `VALIDATOR VOTE ACCOUNT\n${keys[1]}`];
  const deactivated = [`STAKE ACCOUNT\n${keys[0]}`, `STAKER / PAYER\n${payer.address}`];
  const swapReview = ['INPUT (raw units) 10000000', 'MINIMUM OUTPUT (raw units) 999',
    `POOL INPUT ACCOUNT\n${keys[3]}`, `POOL OUTPUT ACCOUNT\n${keys[4]}`, `TO TOKEN ACCOUNT\n${keys[5]}`];
  const wrongLayout = compileTransaction(message(sdkSwap, false));
  reject(argsFor('sol', Buffer.from(wrongLayout.messageBytes).toString('hex')));
  for (const [ix, expected] of [
    [saved(legacy.delegate), delegated], [getDelegateStakeInstruction(stake), delegated],
    [saved(legacy.deactivate), deactivated], [getDeactivateInstruction(stake), deactivated],
    [classicSwap, [...swapReview, `SWAP PROGRAM\n${classicSwap.programAddress}`]],
    [{...classicSwap, programAddress: orca}, [...swapReview, `SWAP PROGRAM\n${orca}`]],
    [getTransferCheckedInstruction({source: keys[2], mint: keys[8], destination: keys[5], authority: payer, amount: 1n, decimals: 0}),
      [`SPL TOKEN MINT\n${keys[8]}`, `FROM TOKEN ACCOUNT\n${keys[2]}`, keys[5], 'RAW UNITS: 1\nDECIMALS: 0']],
  ]) {
    for (const v0 of [false, true]) {
      const m = message(ix, v0);
      const tx = await signTransactionMessageWithSigners(m);
      const args = argsFor('sol', Buffer.from(tx.messageBytes).toString('hex'));
      const result = phone('sol', args[2]);
      for (const text of [...expected, `address=${payer.address}`, `signed=${Buffer.from(getTransactionEncoder().encode(tx)).toString('hex')}`])
        assert.ok(result.includes(text), text);
      const signed = Buffer.from(/^signed=([a-f0-9]+)$/m.exec(result)[1], 'hex');
      const id = bs58.encode(tx.signatures[payer.address]);
      const genesisHash = keys[10];
      const rpc = async (method, params) => {
        if (method === 'getGenesisHash') return genesisHash;
        if (method === 'isBlockhashValid') {
          assert.equal(params[0], keys[11]);
          return {value: true};
        }
        assert.equal(method, 'sendTransaction');
        assert.equal(params[0], signed.toString('base64'));
        assert.equal(params[1].skipPreflight, false);
        return id;
      };
      const submit = {rpc, signed, unsigned: tx.messageBytes, payer: payer.address, genesisHash};
      assert.equal(await broadcastSolana(submit), id);
      const badSignature = Buffer.from(signed);
      badSignature[1] ^= 1;
      await assert.rejects(broadcastSolana({...submit, signed: badSignature}), /signature/);
      await assert.rejects(broadcastSolana({...submit, payer: keys[0]}), /payer/);
      await assert.rejects(broadcastSolana({...submit, genesisHash: keys[6]}), /cluster mismatch/);
      await assert.rejects(broadcastSolana({...submit, unsigned: signed}), /message mismatch/);
      await assert.rejects(broadcastSolana({...submit, rpc: async method => method === 'getGenesisHash' ? genesisHash : {value: false}}), /blockhash/);
      reject([...args, 'tamper']);
      if (!v0) assert.ok(!phone('sol', args[2], 'reject').includes('signed='));
    }
    const foreign = compileTransaction(message({...ix, programAddress: keys[10]}, false));
    reject(argsFor('sol', Buffer.from(foreign.messageBytes).toString('hex')));
  }
}

async function cosmos() {
  const root = HDNodeWallet.fromSeed(seed);
  const memo = 'wallet transfer';
  const gas = 125000;
  const u64 = value => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(value)); return b; };
  const text = value => Buffer.concat([Buffer.from([Buffer.byteLength(value)]), Buffer.from(value)]);
  for (const [network, hrp, chainId, coin, symbol, denom] of [
    ['atom', 'cosmos', 'cosmoshub-4', 118, 'ATOM', 'uatom'], ['osmo', 'osmo', 'osmosis-1', 118, 'OSMO', 'uosmo'],
    ['tia', 'celestia', 'celestia', 118, 'TIA', 'utia'], ['kava', 'kava', 'kava_2222-10', 459, 'KAVA', 'ukava'],
    ['terra', 'terra', 'phoenix-1', 330, 'LUNA', 'uluna'], ['terraclassic', 'terra', 'columbus-5', 330, 'LUNC', 'uluna'],
  ]) {
    const hdPath = `m/44'/${coin}'/0'/0/`;
    const wallet = i => DirectSecp256k1Wallet.fromKey(getBytes(root.derivePath(hdPath + i).privateKey), hrp);
    const signer = await wallet(index);
    const [sender] = await signer.getAccounts();
    const [first] = await (await wallet(index + 1)).getAccounts();
    const [second] = await (await wallet(index + 2)).getAccounts();
    const payments = [[first.address, 1234567], [second.address, 2000000]];
    const messages = payments.map(([toAddress, amount]) => ({typeUrl: '/cosmos.bank.v1beta1.MsgSend',
      value: MsgSend.encode({fromAddress: sender.address, toAddress, amount: [{amount: String(amount), denom}]}).finish()}));
    const bodyBytes = TxBody.encode(TxBody.fromPartial({messages, memo})).finish();
    const pubkey = encodePubkey({type: 'tendermint/PubKeySecp256k1', value: Buffer.from(sender.pubkey).toString('base64')});
    for (const [account, sequence] of [[0, 0], [789, 0], [0, 12], [789, 12]]) {
      const fee = account === 0 && sequence !== 0 ? 0 : 2700;
      const payload = Buffer.concat([Buffer.from([3]), text(chainId), u64(account), u64(sequence), u64(fee), u64(gas),
        text(denom), text(memo), Buffer.from([payments.length]), ...payments.flatMap(([to, amount]) => [u64(amount), text(to)])]);
      const feeCoins = fee === 0 ? [] : [{denom, amount: String(fee)}];
      const authInfoBytes = makeAuthInfoBytes([{pubkey, sequence}], feeCoins, gas, undefined, undefined);
      const {signature} = await signer.signDirect(sender.address, makeSignDoc(bodyBytes, authInfoBytes, chainId, account));
      const expected = TxRaw.encode({bodyBytes, authInfoBytes, signatures: [Buffer.from(signature.signature, 'base64')]}).finish();
      const wire = payload.toString('hex');
      const fields = phone(network, wire).split('\n');
      for (const field of [`path=${hdPath}${index}`, `address=${sender.address}`, first.address, second.address,
        `1.234567 ${symbol}`, `2.000000 ${symbol}`, `${fee ? '0.002700' : '0.000000'} ${symbol}`, chainId,
        `${account} / ${sequence}`, String(gas), memo]) assert.ok(fields.includes(field), `${network} missing ${field}`);
      assert.ok(fields.includes(`signed=${Buffer.from(expected).toString('hex')}`), `${network} TxRaw mismatch at ${account}/${sequence}`);
      if (account === 0 && sequence === 0) assert.ok(!phone(network, wire, 'stale-page').includes('signed='));
    }
    console.log(`${network} ${chainId}: two-recipient MsgSend, zero and nonzero counters matched CosmJS TxRaw`);
    if (network === 'atom' || network === 'osmo') {
      const forward = network === 'atom';
      const channel = forward ? 'channel-141' : 'channel-0';
      const peer = await DirectSecp256k1Wallet.fromKey(getBytes(root.derivePath(hdPath + index).privateKey), forward ? 'osmo' : 'cosmos');
      const [{address: receiver}] = await peer.getAccounts();
      const timeoutNs = 2012345678901234567n;
      const params = {chainId, account: 789, sequence: 12, fee: 2700, gas, amount: 1234567, receiver, timeoutNs};
      const payload = buildIbcTransfer(params);
      const message = MsgTransfer.fromPartial({sourcePort: 'transfer', sourceChannel: channel, sender: sender.address,
        receiver, token: {denom, amount: '1234567'}, timeoutHeight: {}, timeoutTimestamp: timeoutNs});
      const ibcBody = TxBody.encode(TxBody.fromPartial({messages: [{typeUrl: '/ibc.applications.transfer.v1.MsgTransfer',
        value: MsgTransfer.encode(message).finish()}]})).finish();
      const auth = makeAuthInfoBytes([{pubkey, sequence: 12}], [{denom, amount: '2700'}], gas);
      const {signature} = await signer.signDirect(sender.address, makeSignDoc(ibcBody, auth, chainId, 789));
      const expected = TxRaw.encode({bodyBytes: ibcBody, authInfoBytes: auth, signatures: [Buffer.from(signature.signature, 'base64')]}).finish();
      const fields = phone(network, payload.toString('hex')).split('\n');
      for (const value of [receiver, sender.address, `transfer/${channel}`, forward ? 'osmosis-1' : 'cosmoshub-4',
        `${timeoutNs}`, `1.234567 ${symbol}`, `signed=${Buffer.from(expected).toString('hex')}`]) assert.ok(fields.includes(value), value);
      const checkBroadcast = async (operation, proposal, signed) => {
        const hash = createHash('sha256').update(signed).digest('hex').toUpperCase();
        const rpc = async (method, args) => {
          if (method === 'status') return {node_info: {network: chainId}};
          assert.equal(method, 'broadcast_tx_sync');
          assert.deepEqual(args, {tx: Buffer.from(signed).toString('base64')});
          return {hash, code: 0};
        };
        const submit = {rpc, signed, operation, params: proposal, sender: sender.address, publicKey: sender.pubkey};
        assert.equal(await broadcastCosmos(submit), hash);
        return submit;
      };
      const submit = await checkBroadcast('ibcTransfer', params, expected);
      await assert.rejects(broadcastCosmos({...submit, params: {...params, amount: 2n}}), /reviewed transaction mismatch/);
      await assert.rejects(broadcastCosmos({...submit, rpc: async () => ({node_info: {network: 'other'}})}), /RPC chain mismatch/);
      const badChannel = Buffer.from(payload);
      badChannel[badChannel.length - 9] ^= 1;
      for (const bytes of [badChannel, buildIbcTransfer({...params, receiver: sender.address}),
          buildIbcTransfer({...params, timeoutNs: 0n}), Buffer.concat([payload, Buffer.from([0])])])
        reject(['phone-review', network, bytes.toString('hex'), 'approve']);
      console.log(`${chainId} transfer/${channel}: ICS-20 review and signed TxRaw matched CosmJS`);
      const funds = [{denom, amount: '1234567'}];
      const authority = {granter: sender.address, grantee: first.address};
      const expirySeconds = 2012345678n;
      const sendAuth = {typeUrl: SendAuthorization.typeUrl,
        value: SendAuthorization.encode({spendLimit: funds, allowList: []}).finish()};
      for (const [codec, msg, proposal, labels] of [
        [MsgGrant, {...authority, grant: {authorization: sendAuth, expiration: {seconds: expirySeconds, nanos: 0}}},
          buildGrantSend({...params, grantee: first.address, spendLimit: 1234567, expirySeconds}),
          ['GRANT BANK SEND', 'ANY', `SPEND LIMIT 1.234567 ${symbol}`, String(expirySeconds)]],
        [MsgRevoke, {...authority, msgTypeUrl: MsgSend.typeUrl}, buildRevokeSend({...params, grantee: first.address}), ['REVOKE BANK SEND']],
      ]) {
        const body = TxBody.encode(TxBody.fromPartial({messages: [{typeUrl: codec.typeUrl, value: codec.encode(msg).finish()}]})).finish();
        const {signature} = await signer.signDirect(sender.address, makeSignDoc(body, auth, chainId, 789));
        const signed = TxRaw.encode({bodyBytes: body, authInfoBytes: auth, signatures: [Buffer.from(signature.signature, 'base64')]}).finish();
        const fields = phone(network, proposal.toString('hex')).split('\n');
        for (const label of [...labels, 'GRANTEE', first.address, 'GRANTER', sender.address, MsgSend.typeUrl,
          `signed=${Buffer.from(signed).toString('hex')}`]) assert.ok(fields.includes(label), label);
        const authzSubmit = await checkBroadcast(codec === MsgGrant ? 'grantSend' : 'revokeSend',
          {...params, grantee: first.address, spendLimit: 1234567, expirySeconds}, signed);
        await assert.rejects(broadcastCosmos({...authzSubmit, params: {...authzSubmit.params, grantee: second.address}}), /reviewed transaction mismatch/);
      }
      const amino = await Secp256k1Wallet.fromKey(getBytes(root.derivePath(hdPath + index).privateKey), hrp);
      const aminoMessage = {type: 'cosmos-sdk/MsgSend', value: {from_address: sender.address, to_address: first.address, amount: funds}};
      for (const fee of [0, 2700]) {
        const coins = fee ? [{denom, amount: String(fee)}] : [];
        const message = MsgSend.encode({fromAddress: sender.address, toAddress: first.address, amount: funds}).finish();
        const bodyBytes = TxBody.encode(TxBody.fromPartial({messages: [{typeUrl: MsgSend.typeUrl, value: message}]})).finish();
        const authInfoBytes = makeAuthInfoBytes([{pubkey, sequence: 12}], coins, gas, undefined, undefined, 127);
        const {signature} = await amino.signAmino(sender.address, makeAminoDoc([aminoMessage], {amount: coins, gas: String(gas)}, chainId, '', 789, 12));
        const tx = TxRaw.encode({bodyBytes, authInfoBytes, signatures: [Buffer.from(signature.signature, 'base64')]}).finish();
        const fields = phone(network, buildAminoSend({...params, fee, receiver: first.address}).toString('hex')).split('\n');
        for (const label of ['LEGACY AMINO JSON', first.address, `1.234567 ${symbol}`, `signed=${Buffer.from(tx).toString('hex')}`])
          assert.ok(fields.includes(label), label);
        await checkBroadcast('aminoSend', {...params, fee, receiver: first.address}, tx);
      }
      for (const bad of [{grantee: sender.address}, {spendLimit: 0}, {expirySeconds: 0}, {expirySeconds: 253402300800n}]) {
        const grant = buildGrantSend({...params, spendLimit: 1, grantee: first.address, expirySeconds, ...bad});
        reject(['phone-review', network, grant.toString('hex'), 'approve']);
      }
      console.log(`${chainId}: bank grant, revoke and two legacy amino payments matched independent Cosmos signatures`);
    }
  }
}

evmCatalog().then(ethereum).then(solana).then(cosmos).then(() => console.log('EVM, Solana and Cosmos SDK signature checks and ETH/SOL RPC broadcast checks passed'))
  .catch(error => { console.error(error); process.exitCode = 1; });
