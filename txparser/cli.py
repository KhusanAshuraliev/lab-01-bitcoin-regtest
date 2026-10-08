"""Command-line report: ``python -m txparser <RAW_HEX>`` or pipe hex on stdin."""

from __future__ import annotations

import argparse
import json
import sys

from .parser import Transaction, parse_hex
from .script import address_for, classify, disassemble


def _short(h: str, limit: int = 72) -> str:
    return h if len(h) <= limit else f"{h[:limit]}... ({len(h) // 2} bytes)"


def _witness_label(item: bytes) -> str:
    if 70 <= len(item) <= 73 and item[0] == 0x30:
        return f"DER signature, sighash 0x{item[-1]:02x}" + (" (SIGHASH_ALL)" if item[-1] == 1 else "")
    if len(item) == 33 and item[0] in (2, 3):
        return "compressed public key"
    if len(item) == 64:
        return "Schnorr signature (SIGHASH_DEFAULT)"
    return f"{len(item)}-byte item"


def report(tx: Transaction, network: str) -> str:
    L: list[str] = []
    add = L.append
    add("=" * 78)
    add("FIELD-BY-FIELD BREAKDOWN (offset = byte position in the serialised stream)")
    add("=" * 78)
    add(f"{'offset':>6}  {'len':>4}  {'field':<34} value")
    add("-" * 78)
    for f in tx.fields:
        add(f"{f.offset:>6}  {len(f.raw):>4}  {f.name:<34} {_short(f.value, 64)}")

    add("")
    add("=" * 78)
    add("SUMMARY")
    add("=" * 78)
    add(f"txid          : {tx.txid}")
    add(f"wtxid         : {tx.wtxid}")
    add(f"version       : {tx.version}")
    add(f"segwit        : {tx.is_segwit}" + ("  (marker 0x00, flag 0x01 at offsets 4-5)" if tx.is_segwit else ""))
    add(f"locktime      : {tx.locktime}  ({tx.locktime_kind})")
    add(f"size          : {tx.size} bytes")
    add(f"stripped size : {tx.stripped_size} bytes")
    add(f"weight        : {tx.weight} WU  (= 3 x {tx.stripped_size} + {tx.size})")
    add(f"vsize         : {tx.vsize} vB")

    add("")
    add(f"INPUTS ({len(tx.inputs)})")
    for i, txin in enumerate(tx.inputs):
        add(f"  [{i}] at offset {txin.offset}")
        if txin.is_coinbase:
            add("      coinbase input (null outpoint)")
        add(f"      prev txid : {txin.prev_txid_hex}")
        add(f"      prev vout : {txin.prev_vout}")
        add(f"      scriptSig : {_short(txin.script_sig.hex()) or '(empty)'}")
        if txin.script_sig and not txin.is_coinbase:
            add(f"      asm       : {_short(' '.join(disassemble(txin.script_sig)), 90)}")
        rbf = "  (RBF signalled, BIP-125)" if txin.sequence < 0xFFFFFFFE else ""
        add(f"      sequence  : 0x{txin.sequence:08x}{rbf}")
        if tx.is_segwit:
            add(f"      witness   : {len(txin.witness)} item(s)")
            for j, item in enumerate(txin.witness):
                add(f"        [{j}] {len(item):>3} bytes  {_witness_label(item)}")
                add(f"            {_short(item.hex(), 90)}")

    add("")
    add(f"OUTPUTS ({len(tx.outputs)})")
    for i, txout in enumerate(tx.outputs):
        stype, payload = classify(txout.script_pubkey)
        addr = address_for(stype, payload, network)
        add(f"  [{i}] at offset {txout.offset}")
        add(f"      value        : {txout.value_btc} BTC ({txout.value_sat} sat)")
        add(f"      scriptPubKey : {txout.script_pubkey.hex()}")
        add(f"      asm          : {' '.join(disassemble(txout.script_pubkey))}")
        add(f"      type         : {stype}")
        add(f"      address      : {addr if addr else '(none)'}")
    add(f"  total output : {tx.total_output_sat} sat")

    add("")
    add("FEE")
    if tx.is_coinbase:
        add("  coinbase transaction: no fee (it creates the subsidy and collects the block's fees).")
    else:
        add("  not computable from this transaction alone. Bitcoin has no fee field:")
        add("  fee = sum(input values) - sum(output values), and input values are not")
        add("  serialised here -- each lives in the output being spent (prev txid:vout).")
        add("  Looking those up requires a node or UTXO set.")
    return "\n".join(L)


def to_json(tx: Transaction, network: str) -> dict:
    outs = []
    for o in tx.outputs:
        stype, payload = classify(o.script_pubkey)
        outs.append({
            "value_sat": o.value_sat, "value_btc": o.value_btc, "offset": o.offset,
            "script_pubkey": o.script_pubkey.hex(), "asm": " ".join(disassemble(o.script_pubkey)),
            "type": stype, "address": address_for(stype, payload, network),
        })
    return {
        "txid": tx.txid, "wtxid": tx.wtxid, "version": tx.version, "segwit": tx.is_segwit,
        "locktime": tx.locktime, "size": tx.size, "stripped_size": tx.stripped_size,
        "weight": tx.weight, "vsize": tx.vsize,
        "inputs": [{
            "offset": i.offset, "prev_txid": i.prev_txid_hex, "prev_vout": i.prev_vout,
            "script_sig": i.script_sig.hex(), "sequence": f"0x{i.sequence:08x}",
            "witness": [w.hex() for w in i.witness],
        } for i in tx.inputs],
        "outputs": outs,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="txparser", description="Parse a raw Bitcoin transaction.")
    ap.add_argument("hex", nargs="?", help="raw transaction hex (reads stdin if omitted)")
    ap.add_argument("--network", default="regtest", choices=["mainnet", "testnet", "signet", "regtest"])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    data = args.hex if args.hex else sys.stdin.read()
    try:
        tx = parse_hex(data)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(to_json(tx, args.network), indent=2) if args.json else report(tx, args.network))
    return 0
