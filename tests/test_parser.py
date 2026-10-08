"""Tests for the raw transaction parser.

These tests double as the specification for the `[STUDENT TASK]` implementation:
if your own parser passes them, it satisfies requirements 1 to 4 of the lab.

The fixtures are real, historically significant Bitcoin transactions whose
identifiers can be checked against any block explorer.
"""

from __future__ import annotations

import pytest

from txparser import parse_hex, read_compact_size, write_compact_size
from txparser.parser import hash160
from txparser.script import address_for, bech32_encode, classify, disassemble

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

# The coinbase transaction of the genesis block (2009-01-03).
# Its scriptSig famously embeds the Times headline of that day.
GENESIS_COINBASE = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368"
    "616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066"
    "6f722062616e6b73ffffffff0100f2052a0100000043410467"
    "8afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef"
    "38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)
GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

# The first ever Bitcoin payment between two parties (block 170):
# Satoshi Nakamoto to Hal Finney, 10 BTC, with 40 BTC returned as change.
FIRST_PAYMENT = (
    "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704"
    "000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548"
    "ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d"
    "1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f715"
    "9b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1bade"
    "d5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1e"
    "b68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4"
    "c03f999b8643f656b412a3ac00000000"
)
FIRST_PAYMENT_TXID = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"


# --------------------------------------------------------------------------- #
# CompactSize
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected_len"),
    [
        (0, 1),
        (0xFC, 1),  # last single-byte value
        (0xFD, 3),  # first 0xfd-prefixed value
        (0xFFFF, 3),
        (0x10000, 5),
        (0xFFFFFFFF, 5),
        (0x100000000, 9),
    ],
)
def test_compact_size_roundtrip(value: int, expected_len: int) -> None:
    """All four CompactSize length classes must round-trip exactly."""
    encoded = write_compact_size(value)
    assert len(encoded) == expected_len
    decoded, consumed = read_compact_size(encoded, 0)
    assert decoded == value
    assert consumed == expected_len


def test_compact_size_offset_is_respected() -> None:
    """Decoding must work at a non-zero offset, as it does mid-transaction."""
    buf = b"\xde\xad\xbe\xef" + write_compact_size(300)
    value, consumed = read_compact_size(buf, 4)
    assert (value, consumed) == (300, 3)


# --------------------------------------------------------------------------- #
# Legacy transactions
# --------------------------------------------------------------------------- #


def test_genesis_coinbase_fields() -> None:
    tx = parse_hex(GENESIS_COINBASE)

    assert tx.version == 1
    assert tx.is_segwit is False
    assert tx.locktime == 0
    assert len(tx.inputs) == 1
    assert len(tx.outputs) == 1

    # A coinbase input references the null outpoint.
    txin = tx.inputs[0]
    assert txin.is_coinbase
    assert txin.prev_txid == b"\x00" * 32
    assert txin.prev_vout == 0xFFFFFFFF
    assert txin.sequence == 0xFFFFFFFF

    # The Times headline is embedded in the coinbase scriptSig.
    assert b"Chancellor on brink of second bailout for banks" in txin.script_sig

    # 50 BTC subsidy.
    assert tx.outputs[0].value_sat == 50 * 100_000_000
    assert tx.outputs[0].value_btc == "50.00000000"


def test_genesis_txid_is_recomputed_correctly() -> None:
    """The txid must be derived from the bytes, not read from anywhere.

    If this fails, the usual cause is byte order: hashes are serialised
    little-endian but displayed big-endian.
    """
    assert parse_hex(GENESIS_COINBASE).txid == GENESIS_TXID


def test_first_payment_fields() -> None:
    tx = parse_hex(FIRST_PAYMENT)

    assert tx.txid == FIRST_PAYMENT_TXID
    assert tx.is_segwit is False
    assert len(tx.inputs) == 1
    assert len(tx.outputs) == 2

    # 10 BTC to the recipient, 40 BTC back as change: the classic demonstration
    # that a UTXO is consumed whole and the remainder must be returned explicitly.
    assert tx.outputs[0].value_sat == 10 * 100_000_000
    assert tx.outputs[1].value_sat == 40 * 100_000_000
    assert tx.total_output_sat == 50 * 100_000_000

    # The input is not a coinbase: it references a real previous output.
    assert not tx.inputs[0].is_coinbase
    assert tx.inputs[0].prev_vout == 0


def test_legacy_txid_equals_wtxid() -> None:
    """With no witness data the two identifiers coincide by construction."""
    tx = parse_hex(FIRST_PAYMENT)
    assert tx.txid == tx.wtxid


@pytest.mark.parametrize("raw_hex", [GENESIS_COINBASE, FIRST_PAYMENT])
def test_reserialisation_is_byte_identical(raw_hex: str) -> None:
    """Parsing then re-serialising must reproduce the original bytes exactly.

    This is the strongest single check on a parser: it proves no field was
    silently skipped, truncated or reordered.
    """
    tx = parse_hex(raw_hex)
    assert tx.serialise(include_witness=True).hex() == raw_hex


# --------------------------------------------------------------------------- #
# SegWit
# --------------------------------------------------------------------------- #


def _build_segwit_fixture() -> str:
    """Construct a minimal, well-formed SegWit transaction.

    Built rather than pasted so that every byte is accounted for in the test
    itself. One P2WPKH input spending to one P2WPKH output.
    """
    version = (2).to_bytes(4, "little").hex()
    marker_flag = "0001"

    prev_txid_le = ("aa" * 32)  # arbitrary, symmetric so byte order is not confusing
    prev_vout = (0).to_bytes(4, "little").hex()
    script_sig = "00"  # empty: a native SegWit input carries no scriptSig
    sequence = (0xFFFFFFFD).to_bytes(4, "little").hex()  # RBF signalled
    vin = "01" + prev_txid_le + prev_vout + script_sig + sequence

    value = (99_000).to_bytes(8, "little").hex()
    # OP_0 <20-byte key hash>  -> P2WPKH
    spk = "0014" + "bb" * 20
    vout = "01" + value + "16" + spk

    # Witness stack: two items, a 71-byte signature and a 33-byte pubkey.
    witness = "02" + "47" + "cc" * 71 + "21" + "dd" * 33

    locktime = (0).to_bytes(4, "little").hex()

    return version + marker_flag + vin + vout + witness + locktime


SEGWIT_FIXTURE = _build_segwit_fixture()


def test_segwit_marker_and_flag_are_detected() -> None:
    tx = parse_hex(SEGWIT_FIXTURE)
    assert tx.is_segwit is True
    assert tx.version == 2
    assert len(tx.inputs) == 1
    assert len(tx.outputs) == 1


def test_segwit_witness_stack_is_parsed() -> None:
    tx = parse_hex(SEGWIT_FIXTURE)
    witness = tx.inputs[0].witness
    assert len(witness) == 2
    assert len(witness[0]) == 71  # signature
    assert len(witness[1]) == 33  # compressed public key
    # The scriptSig of a native SegWit input is empty; the data moved to the witness.
    assert tx.inputs[0].script_sig == b""


def test_segwit_txid_differs_from_wtxid() -> None:
    """The txid excludes witness data -- this is what fixed malleability."""
    tx = parse_hex(SEGWIT_FIXTURE)
    assert tx.txid != tx.wtxid


def test_segwit_reserialisation_is_byte_identical() -> None:
    tx = parse_hex(SEGWIT_FIXTURE)
    assert tx.serialise(include_witness=True).hex() == SEGWIT_FIXTURE


def test_segwit_weight_discount() -> None:
    """Witness bytes count a quarter as much as base bytes (BIP-141)."""
    tx = parse_hex(SEGWIT_FIXTURE)
    assert tx.weight == tx.stripped_size * 3 + tx.size
    assert tx.vsize == (tx.weight + 3) // 4
    # The discount must make vsize strictly smaller than the raw size.
    assert tx.vsize < tx.size


# --------------------------------------------------------------------------- #
# Script classification and addresses
# --------------------------------------------------------------------------- #


def test_genesis_output_is_p2pk() -> None:
    tx = parse_hex(GENESIS_COINBASE)
    stype, payload = classify(tx.outputs[0].script_pubkey)
    assert stype == "p2pk"
    assert payload is not None
    assert len(payload) == 65  # uncompressed public key


def test_genesis_address_matches_known_value() -> None:
    """The genesis coinbase key hashes to Bitcoin's most famous address."""
    tx = parse_hex(GENESIS_COINBASE)
    _, payload = classify(tx.outputs[0].script_pubkey)
    assert address_for("p2pk", payload, "mainnet") == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_hash160_known_vector() -> None:
    """HASH160 = RIPEMD160(SHA256(x)); guards the pure-Python fallback."""
    assert hash160(b"").hex() == "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"


def test_bech32_bip173_vector() -> None:
    """BIP-173 reference vector for a v0 witness program."""
    program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert bech32_encode("bc", 0, program) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def test_p2wpkh_classification_and_regtest_address() -> None:
    spk = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    stype, payload = classify(spk)
    assert stype == "p2wpkh"
    addr = address_for(stype, payload, "regtest")
    assert addr is not None and addr.startswith("bcrt1q")


def test_p2tr_uses_bech32m_and_witness_version_one() -> None:
    spk = bytes.fromhex("5120" + "ee" * 32)
    stype, payload = classify(spk)
    assert stype == "p2tr"
    addr = address_for(stype, payload, "regtest")
    assert addr is not None and addr.startswith("bcrt1p")


def test_p2pkh_classification() -> None:
    spk = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    stype, payload = classify(spk)
    assert stype == "p2pkh"
    assert payload == b"\x11" * 20


def test_disassembly_of_p2pkh() -> None:
    spk = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    assert disassemble(spk) == [
        "OP_DUP",
        "OP_HASH160",
        "<" + "11" * 20 + ">",
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]


def test_nulldata_has_no_address() -> None:
    stype, payload = classify(bytes.fromhex("6a0548656c6c6f"))
    assert stype == "nulldata"
    assert address_for(stype, payload) is None


# --------------------------------------------------------------------------- #
# Error handling
# --------------------------------------------------------------------------- #


def test_truncated_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="truncated"):
        parse_hex(GENESIS_COINBASE[:80])


def test_trailing_bytes_are_rejected() -> None:
    with pytest.raises(ValueError, match="trailing"):
        parse_hex(GENESIS_COINBASE + "deadbeef")


def test_non_hex_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        parse_hex("not hex at all")
