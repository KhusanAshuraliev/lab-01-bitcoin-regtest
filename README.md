# lab-01-bitcoin-regtest — my Lab 01 implementation

This is my byte-level parser for raw Bitcoin transactions, which I wrote for **OE Blockchain, Lab 01 (Bitcoin Core in regtest)**.
I used the standard library only — I do not use any Bitcoin library anywhere.

## Report

- [My Lab 01 report (PDF)](report/Lab01_Report_Khusan_Ashuraliev.pdf)
- [`evidence/`](evidence/) — the full command transcript, per-step outputs and `summary.json` from my lab run

## Usage

```bash
uv sync
uv run python -m txparser <RAW_TX_HEX>            # field-by-field report with byte offsets
uv run python -m txparser --json <RAW_TX_HEX>     # machine-readable
docker compose exec -T bitcoind bitcoin-cli getrawtransaction <TXID> | uv run python -m txparser
```

`--network mainnet|testnet|signet|regtest` selects address encoding (default `regtest`).

## How I covered the requirements

| # | Requirement | Where I implemented it | How I tested it |
|---|---|---|---|
| 1 | Legacy parsing with byte offsets, re-serialisation | `parser.py` → `parse_transaction`, `Transaction.serialise` | genesis coinbase, block-170 payment, first input at offset 5, contiguous offsets |
| 2 | SegWit: marker/flag, witness stack per input, weight | `parser.py` | SegWit fixture, Part-B-shaped tx (222 / 113 / 561 / 141), first input at offset 7 |
| 3 | CompactSize, all four classes, non-zero offset | `read_compact_size`, `write_compact_size` | 0, 252, 253, 65 535, 65 536, 2³²−1, 2³², 2⁶⁴−1; non-canonical and truncated rejected |
| 4 | txid (stripped serialisation) and wtxid | `Transaction.txid`, `.wtxid` | genesis `4a5e1e4b…7afdeda33b`, legacy txid == wtxid, SegWit differs |
| 5 | Disassembly + classification | `script.py` → `disassemble`, `classify`, `address_for` | p2pk, p2pkh, **p2sh**, p2wpkh, **p2wsh**, p2tr, nulldata, bare multisig, BIP-173/350 vectors |
| — | Robustness | `ValueError` on truncation, trailing bytes, bad hex, bad SegWit flag | `test_extra.py` |

`tests/test_parser.py` is the course's reference suite (31 tests). I copied it **unchanged**.
In `tests/test_extra.py` I added 60 further tests of my own (p2sh/p2wsh, CompactSize boundaries, offsets, robustness, CLI).

```bash
uv run pytest -v      # 91 passed
```

## Layout

| File | What I put there |
|---|---|
| `txparser/parser.py` | CompactSize, byte cursor with offsets, data model, serialisation, txid/wtxid, sizes |
| `txparser/script.py` | opcode table, disassembly, output classification, Base58Check, Bech32/Bech32m |
| `txparser/_ripemd160.py` | pure-Python RIPEMD-160 (OpenSSL 3 often disables it in `hashlib`) |
| `txparser/cli.py` | command-line report |
| `lab/run_lab.py` | my script that runs Lab 01 Parts A–D against the course's Docker node and saves all evidence |

## How I ran the whole lab

With Docker Desktop running and the course repository checked out, I ran:

```bash
uv sync
uv run python lab/run_lab.py --lab-dir <OE_BLOCKCHAIN>/Labs/lab-01-bitcoin-regtest
```

My script resets the regtest chain (`docker compose down -v`), then performs setup and Parts A, B, C and D using
exactly the `bitcoin-cli` commands of the lab README. It writes every command and its output to
`evidence/transcript.txt`, each result to its own file, and the key numbers plus automatic
parser-vs-node checks to `evidence/summary.json`. I pass JSON arguments through `bitcoin-cli -stdin`,
so there are no shell quoting issues.

## My design decisions

- **Byte order.** I keep hashes in serialised (little-endian) order internally; `prev_txid_hex`, `txid` and
  `wtxid` reverse them for display.
- **txid vs wtxid.** I compute `txid = sha256d(serialise(include_witness=False))`; for `wtxid` I hash the full BIP-144 form.
- **No partial results.** Every read goes through a bounds-checked cursor; I treat leftover bytes after `locktime`
  as an error; and as a final self-check I re-serialise the parsed model and compare it to the input.
- **No fee.** I do not print a fee, because it cannot be computed from a transaction alone: the input values live in the outputs being spent.
