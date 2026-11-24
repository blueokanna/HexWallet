// Pass chain_probe, Anvil and optionally an archive RPC URL for the contract tests.
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { createInterface } = require("node:readline");
const { setTimeout: delay } = require("node:timers/promises");
const {
  BrowserProvider,
  HDNodeWallet,
  Interface,
  Mnemonic,
  Transaction,
  getAddress,
  getBytes,
  toQuantity,
} = require("ethers");
const {
  createEthereumConnection,
  announceEthereumProvider,
} = require("../../tools/ethereum_provider.cjs");

// Exercise discovery and a DApp in a real browser document. The browser's
// native binding supplies the sending frame and carries only EIP-1193 calls.
async function connectPage(chrome, origin, provider, icon) {
  const page = await chrome.newPage();
  await page.route("**/*", (route) =>
    route.request().url() === origin + "/"
      ? route.fulfill({
          contentType: "text/html",
          body: "<!doctype html><title>HexWallet DApp test</title>",
        })
      : route.abort(),
  );
  await page.goto(origin);
  await page.exposeBinding("walletRequest", async ({ frame }, request) => {
    assert.equal(frame, page.mainFrame());
    assert.equal(new URL(frame.url()).origin, origin);
    return provider.request(request);
  });
  const path = require("node:path");
  await page.addScriptTag({
    path: path.resolve(
      path.dirname(require.resolve("ethers")),
      "../dist/ethers.umd.min.js",
    ),
  });
  await page.addScriptTag({
    content: `(${announceEthereumProvider})(window, Object.freeze({request: walletRequest}), ${JSON.stringify(icon)})`,
  });
  await page.evaluate(async () => {
    window.wallet = await ethers.BrowserProvider.discover({
      filter: (wallets) => wallets.find((w) => w.name === "HexWallet"),
    });
    if (!window.wallet)
      throw Error("EIP-6963 discovery failed in the document");
  });
  return page;
}

async function run(probe, anvil, archive) {
  const args = [
    "--host",
    "127.0.0.1",
    "--port",
    "0",
    "--chain-id",
    "1",
    "--accounts",
    "0",
  ];
  if (archive)
    args.push("--fork-url", archive, "--fork-block-number", "20000000");
  const child = spawn(anvil, args, { stdio: ["ignore", "pipe", "inherit"] });
  const exited = once(child, "close");
  const wallet = spawn(probe, ["phone-app-pipe"], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  const walletExited = once(wallet, "close");
  const replies = createInterface({ input: wallet.stdout })[
    Symbol.asyncIterator
  ]();
  const deadline = setTimeout(
    () => {
      child.kill();
      wallet.kill();
    },
    archive ? 240000 : 30000,
  );
  let chrome;
  try {
    let url;
    for await (const line of createInterface({ input: child.stdout })) {
      const listening = /Listening on (127\.0\.0\.1:\d+)/.exec(line);
      if (listening) {
        url = "http://" + listening[1];
        break;
      }
    }
    assert.ok(url, "Anvil failed to start");
    let id = 0;
    async function rpc(method, params) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
      });
      assert.ok(response.ok);
      const reply = await response.json();
      if (reply.error) throw new Error(reply.error.message);
      return reply.result;
    }
    const seed = Mnemonic.fromPhrase(
      "abandon ".repeat(11) + "about",
    ).computeSeed();
    const sender =
      HDNodeWallet.fromSeed(seed).derivePath("m/44'/60'/0'/0/3").address;
    let allowed = false,
      decision = "reject",
      reviewPending = false,
      onPending,
      onSigned;
    let wrongRpc = false,
      broadcasts = 0;
    async function walletRpc(method, params) {
      if (method === "eth_chainId" && wrongRpc) return "0x5";
      if (method === "eth_sendRawTransaction") ++broadcasts;
      return rpc(method, params);
    }
    async function exchange(frame) {
      if (reviewPending && frame[0] === 6) {
        wallet.stdin.write(decision + "\n");
        assert.equal((await replies.next()).value, "panel-decided");
        reviewPending = false;
      }
      wallet.stdin.write(frame.toString("hex") + "\n");
      for (;;) {
        const { value, done } = await replies.next();
        assert.equal(done, false, "Firmware harness exited before replying");
        if (!value.startsWith("response=")) continue;
        const reply = Buffer.from(value.slice(9), "hex");
        if (frame[0] === 6 && reply[4] === 1) {
          reviewPending = true;
          if (onPending) await onPending(frame);
        }
        if (frame[0] === 6 && reply[4] === 0 && onSigned)
          return onSigned(reply);
        return reply;
      }
    }
    const origin = "https://dapp.example";
    const settings = {
      origin,
      exchange,
      rpc: walletRpc,
      index: 3,
      approveOrigin: async (site) => site === origin && allowed,
    };
    const connection = createEthereumConnection(settings);
    const { provider } = connection;
    const page = Object.assign(new EventTarget(), {
      crypto: globalThis.crypto,
      CustomEvent,
    });
    const icon =
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jF0kAAAAASUVORK5CYII=";
    let document;
    if (process.env.HEXWALLET_BROWSER) {
      const { chromium } = require("playwright-core");
      chrome = await chromium.launch({
        executablePath: process.env.HEXWALLET_BROWSER,
        headless: true,
      });
      document = await connectPage(chrome, origin, provider, icon);
    }
    const withdraw = announceEthereumProvider(page, provider, icon);
    const browser = await BrowserProvider.discover({
      window: page,
      filter: (wallets) => wallets.find((w) => w.name === "HexWallet"),
    });
    assert.ok(browser, "Ethers DApp did not discover HexWallet");
    assert.deepEqual(await provider.request({ method: "eth_accounts" }), []);
    await assert.rejects(provider.request({ method: "eth_requestAccounts" }), {
      code: 4001,
    });
    allowed = true;
    const accounts = document
      ? await document.evaluate(() => wallet.send("eth_requestAccounts", []))
      : await provider.request({ method: "eth_requestAccounts" });
    assert.deepEqual(accounts, [sender]);
    assert.equal(await (await browser.getSigner()).getAddress(), sender);
    await assert.rejects(
      provider.request({ method: "eth_sendRawTransaction", params: ["0x"] }),
      { code: 4200 },
    );
    const to = "0x1111111111111111111111111111111111111111";
    await assert.rejects(
      provider.request({
        method: "eth_sendTransaction",
        params: [{ from: to, to }],
      }),
      { code: 4100 },
    );
    await assert.rejects(
      provider.request({
        method: "eth_sendTransaction",
        params: [{ from: sender, to, chainId: "0x5" }],
      }),
      { code: 4901 },
    );
    if (archive) {
      const block = await rpc("eth_getBlockByNumber", [
        toQuantity(20000000),
        false,
      ]);
      assert.equal(
        block.hash,
        "0xd24fd73f794058a3807db926d8898c6481e902b7edb91ce0d479d6760f276183",
      );
    }
    const balance = async (address) =>
      BigInt(await rpc("eth_getBalance", [address, "latest"]));
    const initial = 10n ** 18n,
      value = 10n ** 15n,
      previous = await balance(to);
    await rpc("anvil_setBalance", [sender, toQuantity(initial)]);
    async function receiptFor(hash) {
      const until = Date.now() + 60000;
      do {
        const receipt = await rpc("eth_getTransactionReceipt", [hash]);
        if (receipt) {
          assert.equal(receipt.transactionHash, hash);
          assert.equal(receipt.status, "0x1");
          return receipt;
        }
        await delay(250);
      } while (Date.now() < until);
      throw new Error(
        `Local Anvil transaction ${hash} did not receive a receipt`,
      );
    }
    async function submit(fields, client = provider) {
      const head = await rpc("eth_getBlockByNumber", ["latest", false]);
      const tx = {
        from: sender,
        type: "0x2",
        chainId: "0x1",
        maxPriorityFeePerGas: toQuantity(100000000n),
        maxFeePerGas: toQuantity(2n * BigInt(head.baseFeePerGas) + 100000000n),
        to: fields.to,
        gas: toQuantity(fields.gasLimit),
        value: toQuantity(fields.value ?? 0n),
        data: fields.data ?? "0x",
      };
      const hash =
        document && client === provider && decision === "approve" && !onSigned
          ? await document.evaluate(
              (tx) => wallet.send("eth_sendTransaction", [tx]),
              tx,
            )
          : await client.request({
              method: "eth_sendTransaction",
              params: [tx],
            });
      return receiptFor(hash);
    }
    const originalNonce = await rpc("eth_getTransactionCount", [
      sender,
      "pending",
    ]);
    const interrupted = createEthereumConnection(settings);
    await interrupted.provider.request({ method: "eth_requestAccounts" });
    onPending = async (frame) => {
      interrupted.disconnect();
      wallet.stdin.write("field-lost\n");
      assert.equal((await replies.next()).value, "review-cleared");
      reviewPending = false;
      onPending = undefined;
      assert.equal(
        (await exchange(frame))[4],
        5,
        "Review ID must expire after field loss",
      );
    };
    await assert.rejects(
      submit({ to, value, gasLimit: 21000n }, interrupted.provider),
      { code: 4900 },
    );
    await assert.rejects(submit({ to, value, gasLimit: 21000n }), {
      code: 4001,
    });
    assert.equal(
      await rpc("eth_getTransactionCount", [sender, "pending"]),
      originalNonce,
    );
    decision = "approve";
    onSigned = (reply) => {
      wrongRpc = true;
      return reply;
    };
    await assert.rejects(submit({ to, value, gasLimit: 21000n }), {
      code: 4901,
    });
    wrongRpc = false;
    onSigned = (reply) => {
      const approved = Transaction.from(
        "0x" + reply.subarray(7).toString("hex"),
      );
      const other = HDNodeWallet.fromSeed(seed).derivePath("m/44'/60'/0'/0/4");
      approved.signature = other.signingKey.sign(approved.unsignedHash);
      assert.equal(approved.from, other.address);
      const signed = Buffer.from(getBytes(approved.serialized));
      const header = Buffer.from(reply.subarray(0, 7));
      header.writeUInt16LE(signed.length, 5);
      return Buffer.concat([header, signed]);
    };
    await assert.rejects(
      submit({ to, value, gasLimit: 21000n }),
      /sender, chain or reviewed transaction mismatch/,
    );
    onSigned = undefined;
    assert.equal(broadcasts, 0);
    assert.equal(
      await rpc("eth_getTransactionCount", [sender, "pending"]),
      originalNonce,
    );
    const receipt = await submit({ to, value, gasLimit: 21000n });
    const fee = BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice);
    assert.equal(await balance(to), previous + value);
    assert.equal(await balance(sender), initial - value - fee);
    const results = [
      {
        operation: "ETH transfer",
        sender,
        to,
        valueWei: String(value),
        feeWei: String(fee),
        hash: receipt.transactionHash,
        status: receipt.status,
        block: receipt.blockNumber,
      },
    ];
    if (archive) {
      const steth = "0xae7ab96520de3a18e5e111b5eaab095312d7fe84";
      const router = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d";
      const path = [
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      ];
      const abi = new Interface([
        "function submit(address)",
        "function sharesOf(address) view returns (uint256)",
        "function getAmountsOut(uint256,address[]) view returns (uint256[])",
        "function balanceOf(address) view returns (uint256)",
        "function swapExactETHForTokens(uint256,address[],address,uint256)",
      ]);
      async function read(contract, fn, params) {
        const result = await rpc("eth_call", [
          { to: contract, data: abi.encodeFunctionData(fn, params) },
          "latest",
        ]);
        return abi.decodeFunctionResult(fn, result)[0];
      }
      const sharesBefore = await read(steth, "sharesOf", [sender]);
      const stake = await submit({
        to: steth,
        value,
        gasLimit: 350000,
        data: abi.encodeFunctionData("submit", [to]),
      });
      const minted = (await read(steth, "sharesOf", [sender])) - sharesBefore;
      assert.ok(minted > 0n);
      results.push({
        operation: "Lido submit",
        hash: stake.transactionHash,
        status: stake.status,
        sharesMinted: String(minted),
      });
      const expected = (await read(router, "getAmountsOut", [value, path]))[1];
      assert.ok(expected > 0n);
      const tokensBefore = await read(path[1], "balanceOf", [sender]);
      const head = await rpc("eth_getBlockByNumber", ["latest", false]);
      const data = abi.encodeFunctionData("swapExactETHForTokens", [
        expected,
        path,
        sender,
        BigInt(head.timestamp) + 3600n,
      ]);
      const swap = await submit({ to: router, value, gasLimit: 350000, data });
      assert.equal(
        (await read(path[1], "balanceOf", [sender])) - tokensBefore,
        expected,
      );
      results.push({
        operation: "Uniswap V2 ETH to USDC",
        hash: swap.transactionHash,
        status: swap.status,
        usdcRaw: String(expected),
      });

      const collection = "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
        tokenId = 1n;
      const nft = new Interface([
        "function ownerOf(uint256) view returns (address)",
        "function safeTransferFrom(address,address,uint256)",
      ]);
      async function owner() {
        const ownerData = await rpc("eth_call", [
          {
            to: collection,
            data: nft.encodeFunctionData("ownerOf", [tokenId]),
          },
          "latest",
        ]);
        return nft.decodeFunctionResult("ownerOf", ownerData)[0];
      }
      const holder = await owner();
      await rpc("anvil_impersonateAccount", [holder]);
      await rpc("anvil_setBalance", [holder, toQuantity(initial)]);
      const setupHash = await rpc("eth_sendTransaction", [
        {
          from: holder,
          to: collection,
          gas: toQuantity(180000),
          data: nft.encodeFunctionData("safeTransferFrom", [
            holder,
            sender,
            tokenId,
          ]),
        },
      ]);
      await receiptFor(setupHash);
      await rpc("anvil_stopImpersonatingAccount", [holder]);
      assert.equal(await owner(), sender);
      const transfer = await submit({
        to: collection,
        gasLimit: 180000,
        data: nft.encodeFunctionData("safeTransferFrom", [sender, to, tokenId]),
      });
      assert.equal(await owner(), getAddress(to));
      results.push({
        operation: "ERC-721 safeTransferFrom",
        collection,
        tokenId: String(tokenId),
        ownerAfter: to,
        hash: transfer.transactionHash,
        status: transfer.status,
      });
    }
    connection.disconnect();
    await assert.rejects(provider.request({ method: "eth_accounts" }), {
      code: 4900,
    });
    withdraw();
    assert.equal(
      await BrowserProvider.discover({ window: page, timeout: 20 }),
      null,
    );
    browser.destroy();
    if (document)
      console.error(
        "Browser EIP-6963 discovery, account permission and approved submissions passed in Chromium " +
          chrome.version(),
      );
    console.log(JSON.stringify(results, null, 2));
  } finally {
    child.kill();
    wallet.stdin.end();
    wallet.kill();
    clearTimeout(deadline);
    if (chrome) await chrome.close();
    await Promise.all([exited, walletExited]);
  }
}

run(...process.argv.slice(2)).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
