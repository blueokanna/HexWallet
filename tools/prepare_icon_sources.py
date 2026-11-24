"""Prepare reviewed asset identities for downloading original provider artwork.

Inputs are cached GitHub directory and CoinGecko markets responses. Matching
tickers alone is not sufficient: the allowlists below identify the projects.
"""
import json
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
logs = ROOT / "build/audit-logs"
def load(name):
    return json.loads((logs / name).read_text(encoding="utf-8-sig"))
symbols = {row.split('|')[1] for row in (logs / "icon-catalog.txt").read_text(encoding="utf-8-sig").splitlines() if '|' in row}
# PRL in cryptocurrency-icons is Oyster Pearl, not the Pearl chain in this
# wallet. It is deliberately excluded even though the ticker is identical.
cc0 = set('AE ALGO ETH USDC AVAX BNB BTC BCH BTG BSV BTX ADA ATOM DASH DCR DGB DOGE EMC2 ETC FTC FIL FLO GBX GRS ONE ICX ICP KSM LBC LTC MONA XMR XMY NMC XEM DOT QTUM QRL RVN RYO SC SOL XLM XTZ TRX VET VTC VIVO XRP ZEC'.split())
gecko_ids = set('near sui hedera-hashgraph crypto-com-chain okb mantle polygon-ecosystem-token kaspa xdce-crowd-sale flare-networks aptos celestia terra-luna starknet sei-network plasma kaia conflux-token monad ecash acala alephium astar auroracoin axe babacoin bellcoin berachain biblepay canto canxium celo chaincoin cheetahcoin chia coredaoorg cosanta digitalcoin dynamic e-gulden ergo ethereum-pow-iou ether-1 etica evmos fantom firo flow fuse-network garlicoin globalboost xdai helpthehomeless hive junkcoin kava larissa-blockchain mazacoin metis-token moonbeam mooncoin moonriver neoxa nervos-network neurai newenglandcoin newyorkcoin oasis-network octaspace okexchain osmosis quai-network quark raptoreum ritocoin ronin rootstock satoxcoin shibacoin stakecube sugarchain telos terra-luna-2 theta-fuel the-open-network veil vipstarcoin zano zephyr-protocol zero zeroonecoin'.split())
existing = {}
for line in (ROOT / 'assets/icons/icons.txt').read_text().splitlines():
    parts = line.split()
    if parts and not parts[0].startswith('#'):
        existing[parts[0]] = parts[1:]
sources = {}
outline = {item['name']: item for item in load('icon-upstream-outline.json')}
for item in load('icon-upstream-list.json'):
    symbol = item['name'].removesuffix('.png').upper()
    if symbol in cc0 and symbol in symbols:
        local = ROOT / 'assets/icons/32' / item['name']
        if local.exists() and item['name'] in outline:
            data = local.read_bytes()
            if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == outline[item['name']]['sha']:
                item = outline[item['name']]
        sources[symbol] = dict(file=symbol.lower(), keys=existing.get(symbol.lower(), [symbol]),
            provider='cryptocurrency-icons / CC0', url=item['download_url'], source_id=item['sha'])
for item in load('icon-markets.json') + load('icon-extra-markets.json'):
    symbol = item['symbol'].upper()
    if symbol in symbols and item['id'] in gecko_ids and symbol not in sources:
        sources[symbol] = dict(file=symbol.lower(), keys=existing.get(symbol.lower(), [symbol]),
            provider='CoinGecko', source_id=item['id'], name=item['name'], url=item['image'])
paprika_ids = set('aegs-aegisum aur-auroracoin avs-aves axe-axe b1t-bit bbc-babacoin bbp-biblepay bell-bellcoin bera-berachain btn-bitnet cau-canxium chta-cheetahcoin cy-cyberyen-c dgc-digitalcoin efl-e-gulden etho-ethoprotocol firo-firo fsc-fsociety fuse-fuse-network fxtc-fixed-trade-coin gael-gaelium hth-help-the-homeless-coin jgc-jagoancoin maza-maza moon-mooncoin mydoge-mydogecoin myt-mytherra nby-neobytes neng-nengcoin nyc-newyorkcoin okt-okc-token osmi-osmium qrk-quark qtc-quantus rin-rincoin roger-theholyrogercoin scc-stakecubecoin sugar-sugarchain taft-cointaft ton-the-open-network trmp-trumpow ufo-uniform-fiscal-object vbc-virbicoin veil-veil whive-the-whive-protocol wjk-wojakcoin zoc-01coin'.split())
for item in load('icons-paprika.json'):
    symbol = item['symbol'].upper()
    if item['id'] in paprika_ids and symbol in symbols and symbol not in sources:
        sources[symbol] = dict(file=symbol.lower(), keys=[symbol], provider='CoinPaprika', source_id=item['id'], name=item['name'], url=f"https://static.coinpaprika.com/coin/{item['id']}/logo.png")
dest = logs / 'icon-source-candidates.json'
dest.write_text(json.dumps(list(sources.values()), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
missing = sorted(symbols - sources.keys())
print(f'original-artwork={len(sources)}/{len(symbols)} missing={" ".join(missing)}')
