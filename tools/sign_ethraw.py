#!/usr/bin/env python3

import os
import sys
from getpass import getpass
from binascii import hexlify
# from ethereum import utils
# from ethereum import transactions
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
    encode_hex,
    is_same_address,
    to_canonical_address,
)
from eth_typing import Address

from eth.vm.forks.berlin.transactions import (
    BerlinTransactionBuilder,
    BerlinLegacyTransaction
)
from eth.vm.forks.frontier.transactions import (
    FrontierTransaction,
)
from eth.vm.forks.homestead.transactions import (
    HomesteadTransaction,
)
from eth.vm.forks.spurious_dragon.transactions import (
    SpuriousDragonTransaction,
)

EVM_SENDER_KEY  = os.getenv("EVM_SENDER_KEY", None)
EVM_CHAINID     = int(os.getenv("EVM_CHAINID", "15555"))
GAS_PRICE       = int(os.getenv("GAS_PRICE", "150000000000")) #1 GWei
GAS             = int(os.getenv("GAS", "1000000"))          #1m Gas

if len(sys.argv) < 6:
    print("{0} FROM TO AMOUNT INPUT_DATA NONCE".format(sys.argv[0]))
    sys.exit(1)

_from = sys.argv[1].lower()
_from = Address(decode_hex(_from))

_to     = sys.argv[2].lower()
_to = Address(decode_hex(_to))

_amount = int(sys.argv[3])
_data = unhexlify(sys.argv[4])
_nonce = int(sys.argv[5])
_gas_price = GAS_PRICE
_gas       = GAS

transaction_class = BerlinLegacyTransaction


if not EVM_SENDER_KEY:
    EVM_SENDER_KEY = getpass('Enter private key for {0}:'.format(_from))

key = keys.PrivateKey(decode_hex(EVM_SENDER_KEY))

unsigned_tx = transaction_class.create_unsigned_transaction(
    nonce       = _nonce,
    gas_price   = _gas_price,
    gas         = _gas,
    to          = _to,
    value       = _amount,
    data        = _data
)

signed_tx = unsigned_tx.as_signed_transaction(key, EVM_CHAINID)

rlptx = rlp.encode(signed_tx, transaction_class)

print("Eth signed raw transaction is 0x{}".format(rlptx.hex()))
