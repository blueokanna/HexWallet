package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/pearl-research-labs/pearl/node/btcec/schnorr"
	"github.com/pearl-research-labs/pearl/node/btcutil"
	"github.com/pearl-research-labs/pearl/node/btcutil/hdkeychain"
	"github.com/pearl-research-labs/pearl/node/chaincfg"
	"github.com/pearl-research-labs/pearl/node/chaincfg/chainhash"
	"github.com/pearl-research-labs/pearl/node/txscript"
	"github.com/pearl-research-labs/pearl/node/wire"
)

func must(err error) { if err != nil { panic(err) } }

func verify(tx *wire.MsgTx, script []byte, amount int64) error {
	fetcher := txscript.NewCannedPrevOutputFetcher(script, amount)
	vm, err := txscript.NewEngine(script, tx, 0, txscript.StandardVerifyFlags,
		nil, txscript.NewTxSigHashes(tx, fetcher), amount, fetcher)
	if err != nil { return err }
	return vm.Execute()
}

func main() {
	if len(os.Args) != 2 { panic("expected output fixture path") }
	var output bytes.Buffer
	seed := make([]byte, 32)
	for i := range seed { seed[i] = byte(i) }
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams); must(err)
	root, err := master.ECPrivKey(); must(err)
	fingerprint := btcutil.Hash160(root.PubKey().SerializeCompressed())[:4]
	fmt.Fprintf(&output, "pearl-keypath-v1\n%x %x\n", seed, fingerprint)
	// Exercise receive/change paths and values beyond Bitcoin's money range.
	for _, change := range []uint32{0, 1} {
		key := master
		for _, step := range []uint32{86 | hdkeychain.HardenedKeyStart,
			chaincfg.HDCoinTypePearl | hdkeychain.HardenedKeyStart,
			hdkeychain.HardenedKeyStart, change, 0} {
			key, err = key.Derive(step); must(err)
		}
		priv, err := key.ECPrivKey(); must(err)
		tweaked := txscript.TweakTaprootPrivKey(*priv, nil)
		pub := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
		addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(pub), &chaincfg.MainNetParams); must(err)
		script, err := txscript.PayToAddrScript(addr); must(err)
		for _, value := range []int64{100000, 2100000000000001, btcutil.MaxGrain} {
			tx := wire.NewMsgTx(2)
			var prev chainhash.Hash
			for i := range prev { prev[i] = 0x42 }
			input := wire.NewTxIn(wire.NewOutPoint(&prev, 0), nil, nil)
			input.Sequence = 0xfffffffd
			tx.AddTxIn(input)
			tx.AddTxOut(wire.NewTxOut(value - 1000, script))
			var unsigned bytes.Buffer
			must(tx.SerializeNoWitness(&unsigned))
			fmt.Fprintf(&output, "%d %d %s %x %x %x", change, value, addr.EncodeAddress(),
				priv.PubKey().SerializeCompressed(), script, unsigned.Bytes())
			for _, hashType := range []txscript.SigHashType{txscript.SigHashDefault, txscript.SigHashAll} {
				fetcher := txscript.NewCannedPrevOutputFetcher(script, value)
				digest, err := txscript.CalcTaprootSignatureHash(txscript.NewTxSigHashes(tx, fetcher), hashType, tx, 0, fetcher); must(err)
				// Match the firmware's BIP340 deterministic all-zero auxiliary input.
				sig, err := schnorr.Sign(tweaked, digest, schnorr.CustomNonce([32]byte{})); must(err)
				witness := sig.Serialize()
				if hashType != txscript.SigHashDefault { witness = append(witness, byte(hashType)) }
				tx.TxIn[0].SetWitness(wire.TxWitness{witness})
				must(verify(tx, script, value))
				var signed bytes.Buffer
				must(tx.Serialize(&signed))
				bad := append([]byte(nil), witness...); bad[0] ^= 1
				tx.TxIn[0].SetWitness(wire.TxWitness{bad})
				if verify(tx, script, value) == nil { panic("corrupt signature accepted") }
				fmt.Fprintf(&output, " %x %x", digest, signed.Bytes())
			}
			fmt.Fprintln(&output)
		}
	}
	must(os.WriteFile(os.Args[1], output.Bytes(), 0644))
	fmt.Printf("Pearl oracle: 6 cases, 12 valid witnesses, 12 corrupt witnesses rejected; seed %s\n", hex.EncodeToString(seed))
}
