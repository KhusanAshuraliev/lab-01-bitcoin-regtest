"""Raw Bitcoin transaction parsing: CompactSize, byte cursor, data model, txid/wtxid.

Serialisation (BIP-144 for the SegWit variant)::

    legacy : version | n_in | inputs | n_out | outputs | locktime
    segwit : version | 0x00 0x01 | n_in | inputs | n_out | outputs | witnesses | locktime

    input  : prev_txid (32, little-endian) | prev_vout (4) | len | scriptSig | sequence (4)
    output : value (8, little-endian satoshis) | len | scriptPubKey
    witness: n_items | (len | item) * n_items           -- one stack per input

All integers are little-endian. Hashes are *stored* little-endian and *displayed*
big-endian (byte-reversed) -- the classic trap of manual transaction handling.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ._ripemd160 import ripemd160 as _ripemd160_py

SATS_PER_BTC = 100_000_000
SEGWIT_MARKER = 0x00
SEGWIT_FLAG = 0x01


# --------------------------------------------------------------------------- #
# Hashing helpers
# --------------------------------------------------------------------------- #


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Double SHA-256, Bitcoin's standard hash for txids and block hashes."""
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):  # OpenSSL 3 without the legacy provider
        return _ripemd160_py(data)


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) -- the 20-byte hash inside P2PKH / P2WPKH outputs."""
    return ripemd160(sha256(data))


# --------------------------------------------------------------------------- #
# CompactSize (a.k.a. VarInt)
# --------------------------------------------------------------------------- #
#
#   value               encoding
#   0 .. 0xFC           1 byte:  the value itself
#   0xFD .. 0xFFFF      0xFD + uint16 LE     (3 bytes)
#   0x10000 .. 2^32-1   0xFE + uint32 LE     (5 bytes)
#   2^32 .. 2^64-1      0xFF + uint64 LE     (9 bytes)

_CS_CLASSES = {0xFD: (2, 0xFD), 0xFE: (4, 0x10000), 0xFF: (8, 0x100000000)}


def read_compact_size(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a CompactSize at ``offset``. Returns ``(value, bytes_consumed)``.

    Non-canonical encodings (e.g. 0xFD0100 for 1) are rejected, as Bitcoin Core does.
    """
    if offset < 0 or offset >= len(buf):
        raise ValueError(f"truncated: CompactSize expected at offset {offset}, buffer is {len(buf)} bytes")
    prefix = buf[offset]
    if prefix < 0xFD:
        return prefix, 1
    width, minimum = _CS_CLASSES[prefix]
    end = offset + 1 + width
    if end > len(buf):
        raise ValueError(f"truncated: CompactSize with prefix 0x{prefix:02x} at offset {offset} needs {width} more bytes")
    value = int.from_bytes(buf[offset + 1 : end], "little")
    if value < minimum:
        raise ValueError(f"non-canonical CompactSize at offset {offset}: {value} encoded with prefix 0x{prefix:02x}")
    return value, 1 + width


def write_compact_size(value: int) -> bytes:
    """Encode ``value`` as a CompactSize using the shortest (canonical) form."""
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"CompactSize out of range: {value}")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


# --------------------------------------------------------------------------- #
# Byte cursor
# --------------------------------------------------------------------------- #


@dataclass
class Field:
    """One parsed field, kept for the offset-annotated report."""

    offset: int
    raw: bytes
    name: str
    value: str


class _Cursor:
    """Sequential reader that records every field together with its byte offset."""

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0
        self.fields: list[Field] = []

    def _take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > len(self.buf):
            raise ValueError(
                f"truncated: need {n} bytes for {what} at offset {self.pos}, "
                f"only {len(self.buf) - self.pos} left"
            )
        chunk = self.buf[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def bytes_(self, n: int, name: str, show: str | None = None) -> bytes:
        start = self.pos
        chunk = self._take(n, name)
        self.fields.append(Field(start, chunk, name, show if show is not None else chunk.hex()))
        return chunk

    def uint(self, n: int, name: str, fmt: str = "{}") -> int:
        start = self.pos
        chunk = self._take(n, name)
        value = int.from_bytes(chunk, "little")
        self.fields.append(Field(start, chunk, name, fmt.format(value)))
        return value

    def compact_size(self, name: str) -> int:
        start = self.pos
        value, used = read_compact_size(self.buf, self.pos)
        self.pos += used
        self.fields.append(Field(start, self.buf[start : self.pos], name, str(value)))
        return value

    def peek(self, n: int = 1) -> bytes:
        return self.buf[self.pos : self.pos + n]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class TxInput:
    prev_txid: bytes  # 32 bytes, in serialised (little-endian) order
    prev_vout: int
    script_sig: bytes
    sequence: int
    offset: int = 0
    witness: list[bytes] = field(default_factory=list)

    @property
    def prev_txid_hex(self) -> str:
        """Previous txid in display (big-endian) order, as RPCs and explorers show it."""
        return self.prev_txid[::-1].hex()

    @property
    def is_coinbase(self) -> bool:
        return self.prev_txid == b"\x00" * 32 and self.prev_vout == 0xFFFFFFFF

    def serialise(self) -> bytes:
        return (
            self.prev_txid
            + self.prev_vout.to_bytes(4, "little")
            + write_compact_size(len(self.script_sig))
            + self.script_sig
            + self.sequence.to_bytes(4, "little")
        )

    def serialise_witness(self) -> bytes:
        out = write_compact_size(len(self.witness))
        for item in self.witness:
            out += write_compact_size(len(item)) + item
        return out


@dataclass
class TxOutput:
    value_sat: int
    script_pubkey: bytes
    offset: int = 0

    @property
    def value_btc(self) -> str:
        whole, frac = divmod(self.value_sat, SATS_PER_BTC)
        return f"{whole}.{frac:08d}"

    def serialise(self) -> bytes:
        return self.value_sat.to_bytes(8, "little") + write_compact_size(len(self.script_pubkey)) + self.script_pubkey


@dataclass
class Transaction:
    version: int
    inputs: list[TxInput]
    outputs: list[TxOutput]
    locktime: int
    is_segwit: bool = False
    fields: list[Field] = field(default_factory=list, repr=False)

    # -- serialisation -------------------------------------------------------

    def serialise(self, include_witness: bool = True) -> bytes:
        """Re-encode the transaction. ``include_witness=False`` gives the legacy
        (stripped) form over which the txid is computed."""
        with_wit = include_witness and self.is_segwit
        out = self.version.to_bytes(4, "little", signed=False)
        if with_wit:
            out += bytes([SEGWIT_MARKER, SEGWIT_FLAG])
        out += write_compact_size(len(self.inputs))
        for txin in self.inputs:
            out += txin.serialise()
        out += write_compact_size(len(self.outputs))
        for txout in self.outputs:
            out += txout.serialise()
        if with_wit:
            for txin in self.inputs:
                out += txin.serialise_witness()
        out += self.locktime.to_bytes(4, "little")
        return out

    # -- identifiers ---------------------------------------------------------

    @property
    def txid(self) -> str:
        """sha256d of the serialisation WITHOUT witness data, byte-reversed for display."""
        return sha256d(self.serialise(include_witness=False))[::-1].hex()

    @property
    def wtxid(self) -> str:
        """sha256d of the full serialisation (BIP-141). Equals txid for legacy transactions."""
        return sha256d(self.serialise(include_witness=True))[::-1].hex()

    # -- sizes (BIP-141) -----------------------------------------------------

    @property
    def size(self) -> int:
        return len(self.serialise(include_witness=True))

    @property
    def stripped_size(self) -> int:
        return len(self.serialise(include_witness=False))

    @property
    def weight(self) -> int:
        return self.stripped_size * 3 + self.size

    @property
    def vsize(self) -> int:
        return (self.weight + 3) // 4

    # -- convenience ---------------------------------------------------------

    @property
    def total_output_sat(self) -> int:
        return sum(o.value_sat for o in self.outputs)

    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].is_coinbase

    @property
    def locktime_kind(self) -> str:
        """nLockTime < 500 000 000 is a block height, otherwise a UNIX timestamp."""
        if self.locktime == 0:
            return "none"
        return "block height" if self.locktime < 500_000_000 else "unix time"


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def parse_transaction(raw: bytes) -> Transaction:
    """Parse a complete raw transaction. Raises ``ValueError`` on any malformation,
    including truncation and trailing bytes -- never returns a partial result."""
    raw = bytes(raw)
    cur = _Cursor(raw)

    version = cur.uint(4, "version")

    is_segwit = False
    if cur.peek(1) == b"\x00":
        # In a legacy tx this byte would be the input count; zero inputs is invalid,
        # so 0x00 here unambiguously announces the BIP-144 extended format.
        cur.bytes_(1, "marker")
        flag = cur.uint(1, "flag", "0x{:02x}")
        if flag != SEGWIT_FLAG:
            raise ValueError(f"invalid SegWit flag 0x{flag:02x} at offset 5 (expected 0x01)")
        is_segwit = True

    n_in = cur.compact_size("input count")
    if n_in == 0:
        raise ValueError("transaction has no inputs")
    inputs: list[TxInput] = []
    for i in range(n_in):
        start = cur.pos
        prev = cur.bytes_(32, f"input[{i}].prev_txid")
        cur.fields[-1].value = prev[::-1].hex()  # shown big-endian
        vout = cur.uint(4, f"input[{i}].prev_vout")
        slen = cur.compact_size(f"input[{i}].scriptSig length")
        script_sig = cur.bytes_(slen, f"input[{i}].scriptSig")
        seq = cur.uint(4, f"input[{i}].sequence", "0x{:08x}")
        inputs.append(TxInput(prev, vout, script_sig, seq, offset=start))

    n_out = cur.compact_size("output count")
    outputs: list[TxOutput] = []
    for i in range(n_out):
        start = cur.pos
        value = cur.uint(8, f"output[{i}].value")
        cur.fields[-1].value = f"{value} sat"
        slen = cur.compact_size(f"output[{i}].scriptPubKey length")
        spk = cur.bytes_(slen, f"output[{i}].scriptPubKey")
        outputs.append(TxOutput(value, spk, offset=start))

    if is_segwit:
        for i, txin in enumerate(inputs):
            n_items = cur.compact_size(f"witness[{i}] item count")
            for j in range(n_items):
                ilen = cur.compact_size(f"witness[{i}][{j}] length")
                txin.witness.append(cur.bytes_(ilen, f"witness[{i}][{j}]"))

    locktime = cur.uint(4, "locktime")

    if cur.pos != len(raw):
        raise ValueError(f"trailing data: {len(raw) - cur.pos} unparsed bytes after locktime at offset {cur.pos}")

    tx = Transaction(version, inputs, outputs, locktime, is_segwit, cur.fields)
    # Self-check: the model must reproduce the input exactly.
    if tx.serialise(include_witness=True) != raw:  # pragma: no cover - defensive
        raise ValueError("internal error: re-serialisation does not match input")
    return tx


def parse_hex(hex_str: str) -> Transaction:
    """Parse a transaction given as a hex string (whitespace and quotes tolerated)."""
    cleaned = "".join(hex_str.split()).strip('"')
    if not cleaned:
        raise ValueError("empty input: expected hexadecimal transaction data")
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"input is not valid hexadecimal: {exc}") from None
    return parse_transaction(raw)
