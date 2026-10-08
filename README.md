# lab-01-bitcoin-regtest — Lab 01 student implementation

Byte-level parser for raw Bitcoin transactions, written for **OE Blockchain, Lab 01 (Bitcoin Core in regtest)**.
Standard library only — no Bitcoin library is used anywhere.

## Report

- [Lab 01 report (PDF)](report/Lab01_Report_Khusan_Ashuraliev.pdf)
- [`evidence/`](evidence/) — full command transcript, per-step outputs and `summary.json` from the lab run

## Usage

```bash
uv sync
uv run python -m txparser <RAW_TX_HEX>            # field-by-field report with byte offsets
uv run python -m txparser --json <RAW_TX_HEX>     # machine-readable
docker compose exec -T bitcoind bitcoin-cli getrawtransaction <TXID> | uv run python -m txparser
```

`--network mainnet|testnet|signet|regtest` selects address encoding (default `regtest`).

## Requirements coverage

| # | Requirement | Where | Tests |
|---|---|---|---|
| 1 | Legacy parsing with byte offsets, re-serialisation | `parser.py` → `parse_transaction`, `Transaction.serialise` | genesis coinbase, block-170 payment, first input at offset 5, contiguous offsets |
| 2 | SegWit: marker/flag, witness stack per input, weight | `parser.py` | SegWit fixture, Part-B-shaped tx (222 / 113 / 561 / 141), first input at offset 7 |
| 3 | CompactSize, all four classes, non-zero offset | `read_compact_size`, `write_compact_size` | 0, 252, 253, 65 535, 65 536, 2³²−1, 2³², 2⁶⁴−1; non-canonical and truncated rejected |
| 4 | txid (stripped serialisation) and wtxid | `Transaction.txid`, `.wtxid` | genesis `4a5e1e4b…7afdeda33b`, legacy txid == wtxid, SegWit differs |
| 5 | Disassembly + classification | `script.py` → `disassemble`, `classify`, `address_for` | p2pk, p2pkh, **p2sh**, p2wpkh, **p2wsh**, p2tr, nulldata, bare multisig, BIP-173/350 vectors |
| — | Robustness | `ValueError` on truncation, trailing bytes, bad hex, bad SegWit flag | `test_extra.py` |

`tests/test_parser.py` is the course's reference suite (31 tests), copied **unchanged**.
`tests/test_extra.py` adds 60 further tests (p2sh/p2wsh, CompactSize boundaries, offsets, robustness, CLI).

```bash
uv run pytest -v      # 91 passed
```

## Layout

| File | Responsibility |
|---|---|
| `txparser/parser.py` | CompactSize, byte cursor with offsets, data model, serialisation, txid/wtxid, sizes |
| `txparser/script.py` | opcode table, disassembly, output classification, Base58Check, Bech32/Bech32m |
| `txparser/_ripemd160.py` | pure-Python RIPEMD-160 (OpenSSL 3 often disables it in `hashlib`) |
| `txparser/cli.py` | command-line report |
| `lab/run_lab.py` | runs Lab 01 Parts A–D against the course's Docker node and saves all evidence |

## Running the whole lab

With Docker Desktop running and the course repository checked out:

```powershell
uv sync
uv run python lab/run_lab.py --lab-dir "C:\path\to\OE_BLOCKCHAIN\Labs\lab-01-bitcoin-regtest"
```

This resets the regtest chain (`docker compose down -v`), then performs setup, Parts A, B, C and D using
exactly the `bitcoin-cli` commands of the lab README. Every command and its output goes to
`evidence/transcript.txt`, each result to its own file, and the key numbers plus automatic
parser-vs-node checks to `evidence/summary.json`. JSON arguments are passed through `bitcoin-cli -stdin`,
so there are no PowerShell quoting issues.

## Design notes

- **Byte order.** Hashes are kept in serialised (little-endian) order internally; `prev_txid_hex`, `txid` and
  `wtxid` reverse them for display.
- **txid vs wtxid.** `txid = sha256d(serialise(include_witness=False))`; `wtxid` hashes the full BIP-144 form.
- **No partial results.** Every read goes through a bounds-checked cursor; leftover bytes after `locktime`
  are an error; the parsed model is re-serialised and compared to the input as a final self-check.
- **No fee.** The fee cannot be computed from a transaction alone: input values live in the outputs being spent.
