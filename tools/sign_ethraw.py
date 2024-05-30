#!/usr/bin/env python3

import os
import sys
from getpass import getpass
from binascii import hexlify
from ethereum import utils
from ethereum import transactions
from binascii import unhexlify
import rlp
import json
from eth_keys import (
    keys,
)
from eth_keys.datatypes import (
    PrivateKey,
)
from eth_utils import (
    decode_hex,
    is_same_address,
    to_canonical_address,
)

EVM_SENDER_KEY  = os.getenv("EVM_SENDER_KEY", None)
EVM_CHAINID     = int(os.getenv("EVM_CHAINID", "15555"))

if len(sys.argv) < 6:
    print("{0} FROM TO AMOUNT INPUT_DATA NONCE".format(sys.argv[0]))
    sys.exit(1)

_from = sys.argv[1].lower()
if _from[:2] == '0x': _from = _from[2:]

_to     = sys.argv[2].lower()
if _to[:2] == '0x': _to = _to[2:]

_amount = int(sys.argv[3])
nonce = int(sys.argv[5])


# if not EVM_SENDER_KEY:
#     EVM_SENDER_KEY = getpass('Enter private key for {0}:'.format(_from))
# # key = keys.PrivateKey(decode_hex(EVM_SENDER_KEY))
# key = PrivateKey(decode_hex(EVM_SENDER_KEY))


# rlptx = rlp.encode(signed_txn, BerlinLegacyTransaction)


unsigned_tx = transactions.Transaction(
    nonce,
    1000000000,   #1 GWei
    1000000,      #1m Gas
    _to,
    _amount,
    unhexlify(sys.argv[4])
)

if not EVM_SENDER_KEY:
    EVM_SENDER_KEY = getpass('Enter private key for {0}:'.format(_from))


def sign(tx, key, network_id=None):
    """Sign this transaction with a private key.

    A potentially already existing signature would be overridden.
    """
    if network_id is None:
        rawhash = utils.sha3(rlp.encode(transactions.unsigned_tx_from_tx(tx), transactions.UnsignedTransaction))
    else:
        assert 1 <= network_id < 2**63 - 18
        rlpdata = rlp.encode(rlp.infer_sedes(tx).serialize(tx)[
                                :-3] + [network_id, b'', b''])
        rawhash = utils.sha3(rlpdata)
    key = transactions.normalize_key(key)
    v, r, s = utils.ecsign(rawhash, key)
    if network_id is not None:
        v += 8 + network_id * 2
    ret = tx.copy(
        v=v,r=r,s=s
    )
    ret._sender = utils.privtoaddr(key)
    return ret

# rlptx = rlp.encode(unsigned_tx.sign(EVM_SENDER_KEY, EVM_CHAINID), transactions.Transaction)
rlptx = rlp.encode(sign(unsigned_tx, EVM_SENDER_KEY, EVM_CHAINID), transactions.Transaction)

print("Eth signed raw transaction is {}".format(rlptx.hex()))