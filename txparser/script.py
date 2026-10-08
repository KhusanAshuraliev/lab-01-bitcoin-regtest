"""Script disassembly, standard output classification and address encoding.

Address encodings implemented from scratch:
  * Base58Check            -- P2PKH / P2SH (and P2PK shown as its P2PKH address)
  * Bech32  (BIP-173)      -- witness version 0  (P2WPKH, P2WSH)
  * Bech32m (BIP-350)      -- witness version 1+ (P2TR)
"""

from __future__ import annotations

from .parser import hash160, sha256d

# --------------------------------------------------------------------------- #
# Opcodes
# --------------------------------------------------------------------------- #

OP_0 = 0x00
OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x4C, 0x4D, 0x4E
OP_1NEGATE = 0x4F
OP_1, OP_16 = 0x51, 0x60
OP_RETURN = 0x6A
OP_DUP, OP_EQUAL, OP_EQUALVERIFY = 0x76, 0x87, 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG, OP_CHECKMULTISIG = 0xAC, 0xAE

OPCODE_NAMES: dict[int, str] = {
    0x00: "OP_0", 0x4C: "OP_PUSHDATA1", 0x4D: "OP_PUSHDATA2", 0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE", 0x50: "OP_RESERVED",
    0x61: "OP_NOP", 0x62: "OP_VER", 0x63: "OP_IF", 0x64: "OP_NOTIF", 0x65: "OP_VERIF",
    0x66: "OP_VERNOTIF", 0x67: "OP_ELSE", 0x68: "OP_ENDIF", 0x69: "OP_VERIFY", 0x6A: "OP_RETURN",
    0x6B: "OP_TOALTSTACK", 0x6C: "OP_FROMALTSTACK", 0x6D: "OP_2DROP", 0x6E: "OP_2DUP",
    0x6F: "OP_3DUP", 0x70: "OP_2OVER", 0x71: "OP_2ROT", 0x72: "OP_2SWAP", 0x73: "OP_IFDUP",
    0x74: "OP_DEPTH", 0x75: "OP_DROP", 0x76: "OP_DUP", 0x77: "OP_NIP", 0x78: "OP_OVER",
    0x79: "OP_PICK", 0x7A: "OP_ROLL", 0x7B: "OP_ROT", 0x7C: "OP_SWAP", 0x7D: "OP_TUCK",
    0x7E: "OP_CAT", 0x7F: "OP_SUBSTR", 0x80: "OP_LEFT", 0x81: "OP_RIGHT", 0x82: "OP_SIZE",
    0x83: "OP_INVERT", 0x84: "OP_AND", 0x85: "OP_OR", 0x86: "OP_XOR", 0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY", 0x89: "OP_RESERVED1", 0x8A: "OP_RESERVED2",
    0x8B: "OP_1ADD", 0x8C: "OP_1SUB", 0x8D: "OP_2MUL", 0x8E: "OP_2DIV", 0x8F: "OP_NEGATE",
    0x90: "OP_ABS", 0x91: "OP_NOT", 0x92: "OP_0NOTEQUAL", 0x93: "OP_ADD", 0x94: "OP_SUB",
    0x95: "OP_MUL", 0x96: "OP_DIV", 0x97: "OP_MOD", 0x98: "OP_LSHIFT", 0x99: "OP_RSHIFT",
    0x9A: "OP_BOOLAND", 0x9B: "OP_BOOLOR", 0x9C: "OP_NUMEQUAL", 0x9D: "OP_NUMEQUALVERIFY",
    0x9E: "OP_NUMNOTEQUAL", 0x9F: "OP_LESSTHAN", 0xA0: "OP_GREATERTHAN",
    0xA1: "OP_LESSTHANOREQUAL", 0xA2: "OP_GREATERTHANOREQUAL", 0xA3: "OP_MIN", 0xA4: "OP_MAX",
    0xA5: "OP_WITHIN", 0xA6: "OP_RIPEMD160", 0xA7: "OP_SHA1", 0xA8: "OP_SHA256",
    0xA9: "OP_HASH160", 0xAA: "OP_HASH256", 0xAB: "OP_CODESEPARATOR", 0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY", 0xAE: "OP_CHECKMULTISIG", 0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB0: "OP_NOP1", 0xB1: "OP_CHECKLOCKTIMEVERIFY", 0xB2: "OP_CHECKSEQUENCEVERIFY",
    0xB3: "OP_NOP4", 0xB4: "OP_NOP5", 0xB5: "OP_NOP6", 0xB6: "OP_NOP7", 0xB7: "OP_NOP8",
    0xB8: "OP_NOP9", 0xB9: "OP_NOP10", 0xBA: "OP_CHECKSIGADD",
}
for _n in range(1, 17):
    OPCODE_NAMES[0x50 + _n] = f"OP_{_n}"


def iter_ops(script: bytes):
    """Yield ``(opcode, pushed_data_or_None)``. Raises ``ValueError`` on a truncated push."""
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if 0x01 <= op <= 0x4B:
            size = op
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
                raise ValueError("truncated OP_PUSHDATA1 length")
            size = script[i]
            i += 1
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                raise ValueError("truncated OP_PUSHDATA2 length")
            size = int.from_bytes(script[i : i + 2], "little")
            i += 2
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                raise ValueError("truncated OP_PUSHDATA4 length")
            size = int.from_bytes(script[i : i + 4], "little")
            i += 4
        else:
            yield op, None
            continue
        if i + size > n:
            raise ValueError(f"truncated push: {size} bytes declared, {n - i} available")
        yield op, script[i : i + size]
        i += size


def disassemble(script: bytes) -> list[str]:
    """Return the script as a list of opcode mnemonics; pushes are shown as ``<hex>``."""
    out: list[str] = []
    try:
        for op, data in iter_ops(script):
            if data is not None:
                out.append(f"<{data.hex()}>")
            else:
                out.append(OPCODE_NAMES.get(op, f"OP_UNKNOWN_0x{op:02x}"))
    except ValueError as exc:
        out.append(f"[error: {exc}]")
    return out


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def _is_pubkey(b: bytes) -> bool:
    return (len(b) == 33 and b[0] in (2, 3)) or (len(b) == 65 and b[0] == 4)


def classify(spk: bytes) -> tuple[str, object]:
    """Classify a scriptPubKey. Returns ``(type, payload)``.

    payload: pubkey (p2pk), 20-byte hash (p2pkh, p2sh, p2wpkh), 32-byte hash/key
    (p2wsh, p2tr), ``(version, program)`` for unknown witness versions,
    ``(m, [pubkeys], n)`` for bare multisig, the data pushes for nulldata,
    ``None`` for nonstandard scripts.
    """
    n = len(spk)
    # P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if n == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "p2pkh", spk[3:23]
    # P2SH: OP_HASH160 <20> OP_EQUAL
    if n == 23 and spk[:2] == b"\xa9\x14" and spk[22] == OP_EQUAL:
        return "p2sh", spk[2:22]
    # Native SegWit: OP_n <2..40 byte program>
    if 4 <= n <= 42 and (spk[0] == OP_0 or OP_1 <= spk[0] <= OP_16) and spk[1] == n - 2:
        version = 0 if spk[0] == OP_0 else spk[0] - 0x50
        program = spk[2:]
        if version == 0 and len(program) == 20:
            return "p2wpkh", program
        if version == 0 and len(program) == 32:
            return "p2wsh", program
        if version == 1 and len(program) == 32:
            return "p2tr", program
        return "witness_unknown", (version, program)
    # P2PK: <pubkey> OP_CHECKSIG
    if n in (35, 67) and spk[0] == n - 2 and spk[-1] == OP_CHECKSIG and _is_pubkey(spk[1:-1]):
        return "p2pk", spk[1:-1]
    # nulldata: OP_RETURN followed by pushes only (provably unspendable)
    if n >= 1 and spk[0] == OP_RETURN:
        try:
            ops = list(iter_ops(spk[1:]))
        except ValueError:
            return "nonstandard", None
        # Only data pushes (incl. OP_0 and the small-integer opcodes) may follow.
        if any(d is None and not (op == OP_0 or OP_1NEGATE <= op <= OP_16) for op, d in ops):
            return "nonstandard", None
        return "nulldata", [d if d is not None else b"" for _, d in ops]
    # Bare multisig: OP_m <pubkey>... OP_n OP_CHECKMULTISIG
    try:
        ops = list(iter_ops(spk))
    except ValueError:
        return "nonstandard", None
    if (
        len(ops) >= 4
        and ops[-1] == (OP_CHECKMULTISIG, None)
        and OP_1 <= ops[0][0] <= OP_16 and ops[0][1] is None
        and OP_1 <= ops[-2][0] <= OP_16 and ops[-2][1] is None
    ):
        keys = [d for _, d in ops[1:-2]]
        m, k = ops[0][0] - 0x50, ops[-2][0] - 0x50
        if all(d is not None and _is_pubkey(d) for d in keys) and len(keys) == k and m <= k:
            return "multisig", (m, keys, k)
    return "nonstandard", None


# --------------------------------------------------------------------------- #
# Base58Check
# --------------------------------------------------------------------------- #

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(version: int, payload: bytes) -> str:
    data = bytes([version]) + payload
    data += sha256d(data)[:4]
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + out


# --------------------------------------------------------------------------- #
# Bech32 / Bech32m
# --------------------------------------------------------------------------- #

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, witver: int, program: bytes) -> str:
    """Encode a segwit address: Bech32 for v0, Bech32m for v1+ (BIP-350)."""
    const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    data = [witver] + _convertbits(program, 8, 5)
    poly = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #

NETWORKS = {
    #            p2pkh  p2sh  bech32 hrp
    "mainnet": (0x00, 0x05, "bc"),
    "testnet": (0x6F, 0xC4, "tb"),
    "signet": (0x6F, 0xC4, "tb"),
    "regtest": (0x6F, 0xC4, "bcrt"),
}


def address_for(stype: str, payload: object, network: str = "regtest") -> str | None:
    """Address for a classified output, or ``None`` if the type has no address
    (nulldata, multisig, nonstandard)."""
    if network not in NETWORKS:
        raise ValueError(f"unknown network {network!r}")
    p2pkh_ver, p2sh_ver, hrp = NETWORKS[network]
    if stype == "p2pkh":
        return base58check_encode(p2pkh_ver, payload)  # type: ignore[arg-type]
    if stype == "p2pk":
        # P2PK has no address of its own; conventionally shown as the P2PKH of the key.
        return base58check_encode(p2pkh_ver, hash160(payload))  # type: ignore[arg-type]
    if stype == "p2sh":
        return base58check_encode(p2sh_ver, payload)  # type: ignore[arg-type]
    if stype in ("p2wpkh", "p2wsh"):
        return bech32_encode(hrp, 0, payload)  # type: ignore[arg-type]
    if stype == "p2tr":
        return bech32_encode(hrp, 1, payload)  # type: ignore[arg-type]
    if stype == "witness_unknown":
        ver, prog = payload  # type: ignore[misc]
        return bech32_encode(hrp, ver, prog)
    return None
