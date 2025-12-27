import sys
sys.path.insert(0, "./src")  # Add 'src' to Python path

from dilithium_py.dilithium import Dilithium3

import hashlib
import os
import statistics
import time
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

# ----------------------- Parameters -----------------------

BLOCK_SIZE_BYTES = 1000000       # 1 MB block cap
S_BASE_BYTES     = 186             # Non-crypto per-tx bytes (from 4k baseline)
SIG_BYTES        = 2973            # Dilithium signature bytes
ADDR_BYTES       = 32              # 32-byte key-hash (address), NOT full PK
FULL_PK_BYTES    = 1952            # Only used if USE_FULL_PK=True
USE_FULL_PK      = False           # False => 32-byte address model
FORCE_TX_COUNT: Optional[int] = 320  # Fix block to N tx, None = auto-pack

MSG_BYTES = 64   # payload length used in signing

# ----------------------------------------------------------

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def merkle_root(txids: List[bytes]) -> bytes:
    if not txids:
        return b"\x00" * 32
    level = txids[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(sha256d(level[i] + level[i+1]))
        level = nxt
    return level[0]

@dataclass
class TxResult:
    tx_index: int
    size_bytes: int
    sign_time_sec: float
    verify_time_sec: float
    txid_hex: str = field(default="")

def serialize_tx_size_bytes(use_full_pk: bool) -> int:
    if use_full_pk:
        return S_BASE_BYTES + SIG_BYTES + FULL_PK_BYTES
    else:
        return S_BASE_BYTES + SIG_BYTES + ADDR_BYTES

def pack_block(max_block_bytes: int,
               per_tx_size: int,
               force_tx_count: Optional[int] = None) -> Tuple[int, int]:
    max_possible = max_block_bytes // per_tx_size
    if force_tx_count is not None:
        return min(force_tx_count, max_possible), per_tx_size
    return max_possible, per_tx_size

def main():
    per_tx_bytes = serialize_tx_size_bytes(USE_FULL_PK)
    tx_count, per_tx_bytes = pack_block(BLOCK_SIZE_BYTES, per_tx_bytes, FORCE_TX_COUNT)
    block_bytes = tx_count * per_tx_bytes
    assert block_bytes <= BLOCK_SIZE_BYTES, "Block exceeds 1 MB!"

    base_msg = os.urandom(MSG_BYTES - 8) if MSG_BYTES >= 8 else b""

    # ✅ Use your Dilithium3 implementation
    keygen, sign, verify = Dilithium3.keygen, Dilithium3.sign, Dilithium3.verify
    pk, sk = keygen()

    # 🔥 Measure signing + verification time for ONE transaction
    msg = base_msg + (0).to_bytes(8, "little")
    t0 = time.perf_counter()
    sig = sign(sk, msg)
    t1 = time.perf_counter()
    ok = verify(pk, msg, sig)
    t2 = time.perf_counter()
    if not ok:
        raise RuntimeError("Signature verification failed")

    sign_time = t1 - t0
    verify_time = t2 - t1

    # 🔥 Scale up to the entire block
    total_sign_time = sign_time * tx_count
    total_verify_time = verify_time * tx_count

    # Compute Merkle root just for realism
    txids = []
    for i in range(tx_count):
        nonce = i.to_bytes(8, "little")
        msg = base_msg + nonce
        serialized = msg + sig  # reuse signature length
        filler_len = max(0, per_tx_bytes - len(serialized))
        serialized += b"\x00" * filler_len
        txid = sha256d(serialized)
        txids.append(txid)
    root = merkle_root(txids)

    print("-------------------------------------------------------------")
    print(f"Block size: {block_bytes:,} bytes with {tx_count} tx (<=1MB cap OK)")
    print(f"Per-tx size: {per_tx_bytes} bytes")
    print(f"Merkle root: {root.hex()}")
    print("-------------------------------------------------------------")
    print(f"Measured sign time (1 tx): {sign_time:.6f}s")
    print(f"Measured verify time (1 tx): {verify_time:.6f}s")
    print(f"Total block signing time ({tx_count} tx): {total_sign_time:.6f}s")
    print(f"Total block verification time ({tx_count} tx): {total_verify_time:.6f}s")

if __name__ == "__main__":
    main()
