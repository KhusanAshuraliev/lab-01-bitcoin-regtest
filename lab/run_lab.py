"""Run Lab 01 Parts A-D end to end against the course's regtest node and save evidence.

Usage (from the root of this repository):

    uv run python lab/run_lab.py --lab-dir "C:/path/to/OE_BLOCKCHAIN/Labs/lab-01-bitcoin-regtest"

What it does -- exactly the commands of the lab README, in order:
  0. docker compose down -v / up -d   (fresh regtest chain, so the numbers match the README)
  1. setup: create wallet lab01, mine 101 blocks
  A. listunspent, getbalances, gettxoutsetinfo
  B. createrawtransaction (10 BTC + 39.9999 change), sign, decode, send, mine, gettransaction
  C. this repo's parser + the reference parser on the signed hex, both test suites
  D. the same spend WITHOUT change: refused (-25), forced with maxfeerate 0, mined, getblock 2

Every command and its full output is written to evidence/transcript.txt, each result also to
its own file, plus evidence/summary.json with the key numbers and automatic checks.

JSON arguments are passed with `bitcoin-cli -stdin`, which avoids all PowerShell/cmd
quoting problems on Windows.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from txparser import parse_hex  # noqa: E402
from txparser.script import address_for, classify  # noqa: E402

WALLET = "lab01"
FEE = Decimal("0.0001")
SEND = Decimal("10")


class Lab:
    def __init__(self, lab_dir: Path, out: Path) -> None:
        self.lab_dir = lab_dir
        self.out = out
        out.mkdir(parents=True, exist_ok=True)
        self.transcript = open(out / "transcript.txt", "w", encoding="utf-8")
        self.summary: dict = {}

    # -- helpers ---------------------------------------------------------------

    def log(self, text: str) -> None:
        print(text)
        self.transcript.write(text + "\n")
        self.transcript.flush()

    def sh(self, cmd: list[str], *, cwd: Path | None = None, stdin: str | None = None,
           check: bool = True, save: str | None = None, show: str | None = None) -> str:
        shown = show or " ".join(cmd)
        self.log(f"\n$ {shown}")
        if stdin:
            for line in stdin.splitlines():
                self.log(f"  (stdin) {line}")
        res = subprocess.run(cmd, cwd=cwd or self.lab_dir, input=stdin, capture_output=True,
                             text=True, encoding="utf-8")
        output = (res.stdout or "") + (res.stderr or "")
        self.log(output.rstrip())
        if save:
            (self.out / save).write_text(f"$ {shown}\n{output}", encoding="utf-8")
        if check and res.returncode != 0:
            raise SystemExit(f"command failed ({res.returncode}): {shown}")
        return res.stdout.strip() if res.returncode == 0 else output.strip()

    def cli(self, *args: str, wallet: bool = False, stdin_args: list[str] | None = None,
            check: bool = True, save: str | None = None) -> str:
        cmd = ["docker", "compose", "exec", "-T", "bitcoind", "bitcoin-cli"]
        if wallet:
            cmd.append(f"-rpcwallet={WALLET}")
        if stdin_args:
            cmd.append("-stdin")
        cmd += list(args)
        show = " ".join(cmd) + ("" if not stdin_args else "  " + "  ".join(f"'{a}'" for a in stdin_args))
        return self.sh(cmd, stdin="\n".join(stdin_args) + "\n" if stdin_args else None,
                       check=check, save=save, show=show)

    def cli_json(self, *args: str, **kw):
        return json.loads(self.cli(*args, **kw), parse_float=Decimal)

    def section(self, title: str) -> None:
        self.log("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)

    # -- steps -----------------------------------------------------------------

    def start(self, reset: bool) -> None:
        self.section("0. Start a fresh regtest node")
        if reset:
            self.sh(["docker", "compose", "down", "-v"])
        self.sh(["docker", "compose", "up", "-d"])
        for _ in range(30):
            r = subprocess.run(["docker", "compose", "exec", "-T", "bitcoind", "bitcoin-cli",
                                "getblockchaininfo"], cwd=self.lab_dir, capture_output=True, text=True)
            if r.returncode == 0:
                break
            time.sleep(2)
        else:
            raise SystemExit("bitcoind did not become ready (docker compose logs bitcoind)")
        self.cli("getblockchaininfo", save="00_getblockchaininfo.txt")
        info = self.cli_json("getnetworkinfo")
        self.summary["node_version"] = info["subversion"]

    def setup(self) -> None:
        self.section("1. Setup: wallet lab01, mine 101 blocks")
        if WALLET not in self.cli_json("listwallets"):
            if '"name"' not in self.cli("loadwallet", WALLET, check=False):
                self.cli("createwallet", WALLET)
        addr = self.cli("getnewaddress", "mining", wallet=True)
        self.cli("-generate", "101", wallet=True, save="01_generate_101.txt")
        self.summary["mining_address"] = addr
        self.summary["height_after_setup"] = int(self.cli("getblockcount"))
        self.summary["balance_after_setup"] = self.cli("getbalance", wallet=True)

    def part_a(self) -> None:
        self.section("PART A - Observing UTXO state")
        utxos = self.cli_json("listunspent", wallet=True, save="A1_listunspent.txt")
        bals = self.cli_json("getbalances", wallet=True, save="A2_getbalances.txt")
        txo = self.cli_json("gettxoutsetinfo", save="A3_gettxoutsetinfo.txt")
        self.summary["A"] = {
            "listunspent_count": len(utxos),
            "mature_utxo": {k: str(utxos[0][k]) for k in ("txid", "vout", "amount", "confirmations", "spendable")} if utxos else None,
            "trusted": str(bals["mine"]["trusted"]),
            "immature": str(bals["mine"]["immature"]),
            "txoutset_height": txo["height"],
            "txouts": txo["txouts"],
            "total_amount": str(txo["total_amount"]),
        }

    def part_b(self) -> None:
        self.section("PART B - Building a raw transaction by hand")
        utxos = self.cli_json("listunspent", "100", wallet=True, save="B1_listunspent_100.txt")
        u = utxos[0]
        dest = self.cli("getnewaddress", "destination", wallet=True, save="B2_dest_address.txt")
        change_addr = self.cli("getnewaddress", "change", wallet=True, save="B2_change_address.txt")
        amount = Decimal(u["amount"])
        change = amount - SEND - FEE
        self.log(f"\n# B3: change = {amount} - {SEND} - {FEE} = {change}")
        inputs = json.dumps([{"txid": u["txid"], "vout": u["vout"]}])
        outputs = json.dumps([{dest: float(SEND)}, {change_addr: float(change)}])
        raw = self.cli("createrawtransaction", wallet=True, stdin_args=[inputs, outputs], save="B4_createrawtransaction.txt")
        signed = self.cli_json("signrawtransactionwithwallet", wallet=True, stdin_args=[raw], save="B4_sign.txt")
        hexs = signed["hex"]
        (self.out / "B_signed_hex.txt").write_text(hexs + "\n", encoding="utf-8")
        decoded = self.cli_json("decoderawtransaction", stdin_args=[hexs], save="B4_decoderawtransaction.txt")
        txid = self.cli("sendrawtransaction", wallet=True, stdin_args=[hexs], save="B4_sendrawtransaction.txt")
        mempool = self.cli_json("getrawmempool", wallet=True, save="B5_getrawmempool_before.txt")
        blocks = self.cli_json("-generate", "1", wallet=True, save="B5_generate_1.txt")
        mempool_after = self.cli_json("getrawmempool", wallet=True, save="B5_getrawmempool_after.txt")
        gt = self.cli_json("gettransaction", txid, wallet=True, save="B6_gettransaction.txt")
        bal = self.cli("getbalance", wallet=True, save="B7_getbalance.txt")
        self.summary["B"] = {
            "input": {"txid": u["txid"], "vout": u["vout"], "amount": str(amount)},
            "destination": dest, "change_address": change_addr,
            "computed_change": str(change), "chosen_fee": str(FEE),
            "sign_complete": signed["complete"], "signed_hex_len": len(hexs),
            "decoded": {k: decoded[k] for k in ("txid", "hash", "size", "vsize", "weight", "version", "locktime")},
            "txid": txid, "in_mempool_before_mining": txid in mempool, "mempool_after": mempool_after,
            "block": blocks["blocks"][0] if isinstance(blocks, dict) else blocks,
            "gettransaction_fee": str(gt["fee"]), "confirmations": gt["confirmations"],
            "fee_matches": abs(Decimal(gt["fee"])) == FEE,
            "fee_rate_sat_vb": round(int(FEE * 100_000_000) / decoded["vsize"], 2),
            "balance_after": bal,
        }
        self.b_hex, self.b_txid, self.b_decoded = hexs, txid, decoded

    def part_c(self, run_reference: bool) -> None:
        self.section("PART C - Parsing the raw format")
        py = sys.executable
        self.sh([py, "-m", "txparser", self.b_hex], cwd=REPO, save="C1_own_parser_output.txt",
                show="python -m txparser <SIGNED_HEX>   # own implementation")
        self.sh([py, "-m", "txparser", "--json", self.b_hex], cwd=REPO, save="C1_own_parser_output.json",
                show="python -m txparser --json <SIGNED_HEX>")
        self.sh([py, "-m", "pytest", "-v"], cwd=REPO, check=False, save="C2_own_pytest.txt",
                show="python -m pytest -v   # own implementation")
        ref = self.lab_dir / "txparser"
        if run_reference and shutil.which("uv") and ref.exists():
            self.sh(["uv", "sync"], cwd=ref, check=False)
            self.sh(["uv", "run", "python", "-m", "txparser", self.b_hex], cwd=ref, check=False,
                    save="C3_reference_parser_output.txt", show="uv run python -m txparser <SIGNED_HEX>   # reference")
            self.sh(["uv", "run", "pytest", "-v"], cwd=ref, check=False, save="C4_reference_pytest.txt",
                    show="uv run pytest -v   # reference")
            # Requirement check: the reference test-suite run against THIS implementation.
        tx = parse_hex(self.b_hex)
        d = self.b_decoded
        checks = {
            "txid == sendrawtransaction": tx.txid == self.b_txid,
            "wtxid == decoderawtransaction.hash": tx.wtxid == d["hash"],
            "size": (tx.size, d["size"]), "vsize": (tx.vsize, d["vsize"]), "weight": (tx.weight, d["weight"]),
            "stripped_size": tx.stripped_size,
            "segwit": tx.is_segwit, "input0_offset": tx.inputs[0].offset,
            "prev_txid == input": tx.inputs[0].prev_txid_hex == self.summary["B"]["input"]["txid"],
            "sequence": f"0x{tx.inputs[0].sequence:08x}",
            "witness_item_lengths": [len(w) for w in tx.inputs[0].witness],
            "outputs": [(o.value_btc, classify(o.script_pubkey)[0],
                         address_for(*classify(o.script_pubkey), "regtest")) for o in tx.outputs],
        }
        self.summary["C"] = checks
        self.log("\n# automatic comparison with the node:\n" + json.dumps(checks, indent=2, default=str))

    def part_d(self) -> None:
        self.section("PART D - The deliberate mistake (no change output)")
        utxos = self.cli_json("listunspent", "100", wallet=True, save="D1_listunspent_100.txt")
        u = next(x for x in utxos if Decimal(x["amount"]) == Decimal(50))
        dest = self.cli("getnewaddress", "destination-d", wallet=True)
        inputs = json.dumps([{"txid": u["txid"], "vout": u["vout"]}])
        outputs = json.dumps([{dest: float(SEND)}])
        raw = self.cli("createrawtransaction", wallet=True, stdin_args=[inputs, outputs], save="D2_createrawtransaction.txt")
        signed = self.cli_json("signrawtransactionwithwallet", wallet=True, stdin_args=[raw], save="D2_sign.txt")
        hexs = signed["hex"]
        (self.out / "D_signed_hex.txt").write_text(hexs + "\n", encoding="utf-8")
        refused = self.cli("sendrawtransaction", wallet=True, stdin_args=[hexs], check=False,
                           save="D3_sendrawtransaction_refused.txt")
        txid = self.cli("sendrawtransaction", wallet=True, stdin_args=[hexs, "0"], save="D4_sendrawtransaction_maxfeerate0.txt")
        gen = self.cli_json("-generate", "1", wallet=True, save="D5_generate_1.txt")
        bh = gen["blocks"][0]
        block = self.cli_json("getblock", bh, "2", save="D6_getblock_verbosity2.txt")
        gt = self.cli_json("gettransaction", txid, wallet=True, save="D7_gettransaction.txt")
        cb = block["tx"][0]
        own = next(t for t in block["tx"] if t["txid"] == txid)
        self.summary["D"] = {
            "input": {"txid": u["txid"], "vout": u["vout"], "amount": str(u["amount"])},
            "destination": dest, "first_send_error": refused, "txid": txid, "blockhash": bh,
            "block_height": block["height"],
            "coinbase_vout": [{"value": str(v["value"]), "type": v["scriptPubKey"].get("type"),
                               "address": v["scriptPubKey"].get("address")} for v in cb["vout"]],
            "own_tx_index": block["tx"].index(own),
            "own_tx_vout": [str(v["value"]) for v in own["vout"]],
            "gettransaction_fee": str(gt["fee"]),
            "own_parser_txid_matches": parse_hex(hexs).txid == txid,
        }

    def finish(self) -> None:
        self.section("Final state")
        self.summary["final_balance"] = self.cli("getbalance", wallet=True)
        self.cli("getbalances", wallet=True, save="Z_getbalances_final.txt")
        (self.out / "summary.json").write_text(json.dumps(self.summary, indent=2, default=str), encoding="utf-8")
        self.log(f"\nEvidence written to: {self.out}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lab-dir", required=True, type=Path, help="folder containing docker-compose.yml")
    ap.add_argument("--out", type=Path, default=REPO / "evidence")
    ap.add_argument("--no-reset", action="store_true", help="do not wipe the regtest chain first")
    ap.add_argument("--no-reference", action="store_true", help="skip running the reference parser")
    args = ap.parse_args()
    lab_dir = args.lab_dir.resolve()
    if not (lab_dir / "docker-compose.yml").exists():
        raise SystemExit(f"{lab_dir} does not contain docker-compose.yml")
    lab = Lab(lab_dir, args.out.resolve())
    lab.start(reset=not args.no_reset)
    lab.setup()
    lab.part_a()
    lab.part_b()
    lab.part_c(run_reference=not args.no_reference)
    lab.part_d()
    lab.finish()


if __name__ == "__main__":
    main()
