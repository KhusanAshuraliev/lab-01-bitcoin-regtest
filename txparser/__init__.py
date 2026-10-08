"""Byte-level Bitcoin transaction parser (OE Blockchain, Lab 01 -- student implementation).

Public API::

    from txparser import parse_hex, parse_transaction
    from txparser.script import disassemble, classify, address_for

Standard library only: no Bitcoin library is used anywhere.
"""

from .parser import (
    Transaction,
    TxInput,
    TxOutput,
    hash160,
    parse_hex,
    parse_transaction,
    read_compact_size,
    sha256d,
    write_compact_size,
)

__all__ = [
    "Transaction",
    "TxInput",
    "TxOutput",
    "hash160",
    "parse_hex",
    "parse_transaction",
    "read_compact_size",
    "sha256d",
    "write_compact_size",
]

__version__ = "1.0.0"
