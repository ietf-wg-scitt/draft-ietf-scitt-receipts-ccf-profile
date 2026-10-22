#!/usr/bin/env python3
"""Check the sample consistency receipts using the Figure 9 checks.

Each .cbor file is one consistency receipt, a tagged COSE_Sign1 with one or
more ccf-consistency-proof values in vdp[-2], signed over the detached newer
root with the public P-384 key in keys.cbor. older-roots.json gives the older
root each receipt is checked against.

Each receipt must fail its named check: newer-root-* the common newer root,
first-sibling-* the first sibling. In a diagnostic run, that check is disabled
and the first computed newer root is retained as the signature payload. The
receipt must then verify. Retaining the first root is equivalent to Figure 9
while the common-root check is enabled. Figure 9 itself assigns the payload
on every iteration, so the diagnostic run is not a literal single-line
deletion from that algorithm.

This checker covers these fixtures, not all profile validation requirements.
validate-cbor-examples.sh separately checks the receipts against CCF_Receipt.

  pip install cbor2 cryptography
  python3 verify.py [samples/consistency-receipts]
"""
import glob
import hashlib
import io
import json
import os
import sys
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

VDP, CONSISTENCY_PROOF = 396, -2
CHECKS = {"newer-root-": "common newer root", "first-sibling-": "first sibling"}


def H(data):
    return hashlib.sha256(data).digest()


def read_key(root):
    """The one P-384 key of the COSE_KeySet in keys.cbor."""
    with open(os.path.join(root, "keys.cbor"), "rb") as f:
        (key,) = cbor2.loads(f.read())
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP384R1())
    return numbers.public_key()


def compute_roots(proof):
    """compute_roots from the draft, over the decoded ccf-consistency-proof map."""
    older = newer = proof[1]
    for left, digest in proof[2]:
        if left:
            older = H(digest + older)
            newer = H(digest + newer)
        else:
            newer = H(newer + digest)
    return older, newer


def verify_cose(protected, signature, payload, key):
    """ES384 over the Sig_structure of RFC 9052 Section 4.4 with the detached payload."""
    tbs = cbor2.dumps(["Signature1", protected, b"", payload])
    if len(signature) != 96:
        return False
    der = utils.encode_dss_signature(int.from_bytes(signature[:48], "big"), int.from_bytes(signature[48:], "big"))
    try:
        key.verify(der, tbs, ec.ECDSA(hashes.SHA384()))
    except InvalidSignature:
        return False
    return True


def verify_consistency_receipt(raw, older_root, key, skip=None):
    """Apply the Figure 9 checks to these fixtures.

    Returns "verifies" or the check that fails. The diagnostic skip mode
    disables one check and retains the first computed newer root as the
    signature payload.
    """
    try:
        fp = io.BytesIO(raw)
        receipt = cbor2.load(fp)
        if fp.read(1):
            raise ValueError("trailing bytes after the receipt")
    except Exception as e:
        return f"receipt is not valid CBOR: {e}"
    if not (isinstance(receipt, cbor2.CBORTag) and receipt.tag == 18 and len(receipt.value) == 4):
        return "not a tagged COSE_Sign1"
    protected, unprotected, payload, signature = receipt.value
    try:
        fp = io.BytesIO(protected)
        header = cbor2.load(fp)
        if fp.read(1):
            raise ValueError("trailing bytes after the map")
    except Exception as e:
        return f"protected header is not valid CBOR: {e}"
    if not isinstance(header, Mapping):
        return "protected header"
    vdp = unprotected.get(VDP) if isinstance(unprotected, Mapping) else None
    if not isinstance(vdp, Mapping):
        return "no vdp map"
    proofs = vdp.get(CONSISTENCY_PROOF)
    if not (isinstance(proofs, (list, tuple)) and proofs):
        return "no consistency proof"
    if payload is not None:
        return "payload is not detached"
    common, older_root_found = None, False
    for proof_bytes in proofs:
        if not isinstance(proof_bytes, bytes):
            return "proof is not a byte string"
        try:
            fp = io.BytesIO(proof_bytes)
            proof = cbor2.load(fp)
            if fp.read(1):
                raise ValueError("trailing bytes after the map")
        except Exception as e:
            return f"proof is not valid CBOR: {e}"
        if skip != "first sibling" and proof[2][0][0] is not False:
            return "first sibling"
        older, newer = compute_roots(proof)
        if skip != "common newer root" and not (common is None or newer == common):
            return "common newer root"
        common = newer if common is None else common
        if older == older_root:
            older_root_found = True
    if not older_root_found:
        return "older root"
    if not verify_cose(protected, signature, common, key):
        return "signature"
    return "verifies"


def main(root):
    key = read_key(root)
    with open(os.path.join(root, "older-roots.json"), encoding="utf-8") as f:
        older_roots = json.load(f)
    paths = sorted(glob.glob(os.path.join(root, "invalid", "*.cbor")))
    if not paths:
        sys.exit(f"no receipts under {root}/invalid")
    failures = 0
    for path in paths:
        name = os.path.relpath(path, root)
        expected = [check for prefix, check in CHECKS.items() if os.path.basename(path).startswith(prefix)]
        with open(path, "rb") as f:
            raw = f.read()
        older_root = bytes.fromhex(older_roots[name])
        got = verify_consistency_receipt(raw, older_root, key)
        without = verify_consistency_receipt(raw, older_root, key, skip=expected[0]) if expected else None
        ok = len(expected) == 1 and got == expected[0] and without == "verifies"
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {got}; without that check: {without}")
        failures += not ok
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))))
