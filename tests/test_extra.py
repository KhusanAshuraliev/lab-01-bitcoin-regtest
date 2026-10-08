"""Additional tests beyond the reference suite: requirement 5 (p2sh, p2wsh, ...),
CompactSize boundaries, byte offsets, a Part-B-shaped transaction and robustness."""

from __future__ import annotations

import hashlib

import pytest

from txparser import parse_hex, read_compact_size, write_compact_size
from txparser._ripemd160 import ripemd160 as ripemd160_py
from txparser.cli import main
from txparser.script import address_for, base58check_encode, bech32_encode, classify, disassemble

from .test_parser import FIRST_PAYMENT, GENESIS_COINBASE, SEGWIT_FIXTURE

# --------------------------------------------------------------------------- #
# Requirement 3 -- CompactSize: every boundary named in the lab
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "encoding"),
    [
        (0, "00"),
        (252, "fc"),
        (253, "fdfd00"),
        (65_535, "fdffff"),
        (65_536, "fe00000100"),
        (2**32 - 1, "feffffffff"),
        (2**32, "ff0000000001000000"),
        (2**64 - 1, "ffffffffffffffffff"),
    ],
)
def test_compact_size_exact_encodings(value: int, encoding: str) -> None:
    assert write_compact_size(value).hex() == encoding
    assert read_compact_size(bytes.fromhex(encoding)) == (value, len(encoding) // 2)


@pytest.mark.parametrize("value", [0, 252, 253, 65_535, 65_536, 2**32 - 1, 2**32])
def test_compact_size_nonzero_offset_all_classes(value: int) -> None:
    buf = b"\x99" * 7 + write_compact_size(value) + b"\x99"
    assert read_compact_size(buf, 7) == (value, len(write_compact_size(value)))


@pytest.mark.parametrize("encoding", ["fd0100", "fefc000000", "ffffff000000000000"])
def test_compact_size_non_canonical_rejected(encoding: str) -> None:
    with pytest.raises(ValueError, match="non-canonical"):
        read_compact_size(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding", ["", "fd", "fd01", "fe010000", "ff01"])
def test_compact_size_truncated_rejected(encoding: str) -> None:
    with pytest.raises(ValueError, match="truncated"):
        read_compact_size(bytes.fromhex(encoding))


def test_compact_size_out_of_range() -> None:
    with pytest.raises(ValueError):
        write_compact_size(-1)
    with pytest.raises(ValueError):
        write_compact_size(2**64)


# --------------------------------------------------------------------------- #
# Requirements 1 & 2 -- byte offsets
# --------------------------------------------------------------------------- #


def test_legacy_first_input_at_offset_5() -> None:
    assert parse_hex(GENESIS_COINBASE).inputs[0].offset == 5
    assert parse_hex(FIRST_PAYMENT).inputs[0].offset == 5


def test_segwit_first_input_at_offset_7() -> None:
    assert parse_hex(SEGWIT_FIXTURE).inputs[0].offset == 7


def test_first_payment_prev_txid_display_order() -> None:
    # Block 9 coinbase, spent by the first payment; shown big-endian as explorers do.
    tx = parse_hex(FIRST_PAYMENT)
    assert tx.inputs[0].prev_txid_hex == "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"


def test_field_offsets_are_contiguous() -> None:
    """Every byte of the transaction belongs to exactly one reported field."""
    for raw in (GENESIS_COINBASE, FIRST_PAYMENT, SEGWIT_FIXTURE):
        tx = parse_hex(raw)
        pos = 0
        for f in tx.fields:
            assert f.offset == pos
            pos += len(f.raw)
        assert pos == len(raw) // 2


def _part_b_shaped() -> str:
    """1 P2WPKH input -> 2 P2WPKH outputs (10 BTC + 39.9999 BTC), 71-byte sig, 33-byte key."""
    return (
        "02000000" + "0001"
        + "01" + "11" * 32 + "00000000" + "00" + "fdffffff"
        + "02"
        + (1_000_000_000).to_bytes(8, "little").hex() + "16" + "0014" + "22" * 20
        + (3_999_990_000).to_bytes(8, "little").hex() + "16" + "0014" + "33" * 20
        + "02" + "47" + "30" + "44" * 69 + "01" + "21" + "02" + "55" * 32
        + "00000000"
    )


def test_part_b_shape_sizes_match_lab_expectations() -> None:
    tx = parse_hex(_part_b_shaped())
    assert tx.is_segwit
    assert (tx.size, tx.stripped_size, tx.weight, tx.vsize) == (222, 113, 561, 141)
    assert tx.weight == 3 * tx.stripped_size + tx.size
    assert tx.inputs[0].sequence == 0xFFFFFFFD
    assert [o.value_btc for o in tx.outputs] == ["10.00000000", "39.99990000"]
    assert all(classify(o.script_pubkey)[0] == "p2wpkh" for o in tx.outputs)
    assert tx.txid != tx.wtxid


# --------------------------------------------------------------------------- #
# Requirement 5 -- classification beyond the reference suite
# --------------------------------------------------------------------------- #


def test_p2sh_classification_disassembly_and_address() -> None:
    h = bytes.fromhex("e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a")
    spk = b"\xa9\x14" + h + b"\x87"
    stype, payload = classify(spk)
    assert stype == "p2sh"
    assert payload == h
    assert disassemble(spk) == ["OP_HASH160", f"<{h.hex()}>", "OP_EQUAL"]
    # Known mainnet P2SH address for this script hash (version byte 0x05 -> '3...').
    assert address_for(stype, payload, "mainnet") == "3P14159f73E4gFr7JterCCQh9QjiTjiZrG"
    assert address_for(stype, payload, "regtest").startswith("2")


def test_p2wsh_classification_and_bip173_vector() -> None:
    prog = bytes.fromhex("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
    spk = b"\x00\x20" + prog
    stype, payload = classify(spk)
    assert stype == "p2wsh"
    assert disassemble(spk) == ["OP_0", f"<{prog.hex()}>"]
    # BIP-173 test vector (testnet P2WSH).
    assert address_for(stype, payload, "testnet") == (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    )
    assert address_for(stype, payload, "regtest").startswith("bcrt1q")


def test_p2wpkh_disassembly() -> None:
    spk = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    assert disassemble(spk) == ["OP_0", "<751e76e8199196d454941c45d1b3a323f1433bd6>"]


def test_p2tr_bip350_vector() -> None:
    prog = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    assert classify(b"\x51\x20" + prog) == ("p2tr", prog)
    assert bech32_encode("bc", 1, prog) == "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"


def test_p2pk_compressed() -> None:
    key = bytes.fromhex("02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    spk = b"\x21" + key + b"\xac"
    assert classify(spk) == ("p2pk", key)


def test_bare_multisig() -> None:
    k1, k2 = b"\x02" + b"\x11" * 32, b"\x03" + b"\x22" * 32
    spk = b"\x51" + b"\x21" + k1 + b"\x21" + k2 + b"\x52" + b"\xae"
    stype, payload = classify(spk)
    assert stype == "multisig"
    assert payload == (1, [k1, k2], 2)
    assert address_for(stype, payload) is None


def test_nulldata_payload_and_disassembly() -> None:
    spk = bytes.fromhex("6a0548656c6c6f")
    assert classify(spk) == ("nulldata", [b"Hello"])
    assert disassemble(spk) == ["OP_RETURN", "<48656c6c6f>"]
    # The witness-commitment output of every SegWit coinbase is also nulldata.
    commitment = bytes.fromhex("6a24aa21a9ed" + "00" * 32)
    assert classify(commitment)[0] == "nulldata"


def test_nonstandard_and_truncated_push() -> None:
    assert classify(b"\x51")[0] == "nonstandard"
    assert disassemble(b"\x4c") == ["[error: truncated OP_PUSHDATA1 length]"]
    assert disassemble(b"\x05\x01")[-1].startswith("[error: truncated push")


def test_pushdata_variants() -> None:
    assert disassemble(b"\x4c\x02\xab\xcd") == ["<abcd>"]
    assert disassemble(b"\x4d\x01\x00\xee") == ["<ee>"]
    assert disassemble(b"\x4e\x01\x00\x00\x00\xff") == ["<ff>"]


def test_base58_leading_zero_bytes() -> None:
    assert base58check_encode(0x00, b"\x00" * 20) == "1111111111111111111114oLvT2"


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("msg", "digest"),
    [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"a" * 1000, "aa69deee9a8922e92f8105e007f76110f381e9cf"),
    ],
)
def test_pure_python_ripemd160_vectors(msg: bytes, digest: str) -> None:
    assert ripemd160_py(msg).hex() == digest


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cut", [2, 8, 10, 100, 150, 300])
def test_truncation_anywhere_is_rejected(cut: int) -> None:
    for raw in (FIRST_PAYMENT, SEGWIT_FIXTURE):
        with pytest.raises(ValueError, match="truncated"):
            parse_hex(raw[:cut])


def test_trailing_bytes_segwit() -> None:
    with pytest.raises(ValueError, match="trailing"):
        parse_hex(SEGWIT_FIXTURE + "00")


@pytest.mark.parametrize("bad", ["", "   ", "abc", "zz", "0x0100"])
def test_bad_hex_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_hex(bad)


def test_invalid_segwit_flag_rejected() -> None:
    bad = SEGWIT_FIXTURE[:10] + "02" + SEGWIT_FIXTURE[12:]
    with pytest.raises(ValueError, match="flag"):
        parse_hex(bad)


def test_whitespace_and_quotes_tolerated() -> None:
    assert parse_hex(f'"{FIRST_PAYMENT}"\n').txid == parse_hex(FIRST_PAYMENT).txid


def test_hashlib_and_fallback_agree() -> None:
    try:
        ref = hashlib.new("ripemd160", b"lab01").digest()
    except ValueError:
        pytest.skip("OpenSSL has no ripemd160 here; fallback covered by vectors")
    assert ripemd160_py(b"lab01") == ref


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_report(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([SEGWIT_FIXTURE]) == 0
    out = capsys.readouterr().out
    assert "segwit        : True" in out
    assert "not computable" in out


def test_cli_error_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["deadbeef"]) == 1
    assert "truncated" in capsys.readouterr().err
