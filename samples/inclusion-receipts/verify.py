#!/usr/bin/env python3
"""Check fixed inclusion-receipt fixtures with a Python adaptation of the draft pseudocode.

The fixtures use the public P-384 key in keys.cbor, ES384, and the fixed test
digest SHA-256 of the ASCII encoding of statement. No Signed Statement is
included, parsed or verified.

The positive fixture must verify. signature-* must fail signature verification
both with and without proof validation and the statement-digest comparison.
cddl-root-as-leaf-* must fail the data-hash size check, and utf8-root-as-leaf-*
must fail strict CBOR decoding. These latter two fixtures must verify when
proof validation and the statement-digest comparison are disabled.

This checker covers these fixtures, not all profile validation requirements.
It does not detect duplicate map keys or independently validate the complete
vdp schema. validate-cbor-examples.sh separately checks the receipt schemas.

  pip install cbor2 cryptography
  python3 verify.py [samples/inclusion-receipts]
"""
import glob
import hashlib
import io
import os
import sys
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

STATEMENT_DIGEST = hashlib.sha256(b"statement").digest()
VDS, VDP, INCLUSION_PROOF = 395, 396, -1


def H(data):
    return hashlib.sha256(data).digest()


class Refused(Exception):
    pass


def read_key(root):
    """The one P-384 key of the COSE_KeySet in keys.cbor."""
    with open(os.path.join(root, "keys.cbor"), "rb") as f:
        (key,) = cbor2.loads(f.read())
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP384R1())
    return numbers.public_key()


def validate_ccf_inclusion_proof(proof):
    """Check the decoded proof shapes exercised by these fixtures."""
    if not (isinstance(proof, dict) and set(proof) == {1, 2}):
        raise Refused("map keys")
    leaf, path = proof[1], proof[2]
    if not (isinstance(leaf, list) and len(leaf) == 3):
        raise Refused("leaf")
    its, evidence, data_hash = leaf
    if not (isinstance(its, bytes) and len(its) == 32):
        raise Refused("internal-transaction-hash")
    if not (isinstance(evidence, str) and 1 <= len(evidence.encode("utf-8")) <= 1024):
        raise Refused("internal-evidence")
    if not (isinstance(data_hash, bytes) and len(data_hash) == 32):
        raise Refused("data-hash")
    if not isinstance(path, list):
        raise Refused("path")
    for element in path:
        if not (isinstance(element, list) and len(element) == 2 and isinstance(element[0], bool)
                and isinstance(element[1], bytes) and len(element[1]) == 32):
            raise Refused("path element")


def compute_root(proof):
    """Adapt the draft's root calculation; surrogateescape preserves bytes for the unchecked UTF-8 test."""
    its, evidence, data_hash = proof[1]
    evidence_bytes = evidence.encode("utf-8", "surrogateescape")
    h = H(its + H(evidence_bytes) + data_hash)
    for left, digest in proof[2]:
        h = H(digest + h) if left else H(h + digest)
    return h


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


def verify_inclusion_receipt(raw, key, checks=True):
    """Adapt the inclusion-verification pseudocode for these fixed fixtures.

    checks=False skips proof validation and the statement-digest comparison, and
    preserves invalid UTF-8 bytes in proof text. Receipt-header checks and signature
    verification remain active.
    """
    try:
        fp = io.BytesIO(raw)
        receipt = cbor2.load(fp)
        if fp.read(1):
            raise ValueError("trailing bytes after the receipt")
    except Exception as e:
        raise Refused(f"receipt is not valid CBOR: {e}")
    if not (isinstance(receipt, cbor2.CBORTag) and receipt.tag == 18 and len(receipt.value) == 4):
        raise Refused("not a tagged COSE_Sign1")
    protected_bytes, unprotected, payload, signature = receipt.value
    try:
        fp = io.BytesIO(protected_bytes)
        protected = cbor2.load(fp)
        if fp.read(1):
            raise ValueError("trailing bytes after the map")
    except Exception as e:
        raise Refused(f"protected header is not valid CBOR: {e}")
    if not isinstance(protected, Mapping) or protected.get(VDS) != 2 or protected.get(1) != -35:
        raise Refused("protected header")
    if payload is not None:
        raise Refused("payload is not detached")
    vdp = unprotected.get(VDP) if isinstance(unprotected, Mapping) else None
    if not isinstance(vdp, Mapping):
        raise Refused("no vdp map")
    proofs = vdp.get(INCLUSION_PROOF)
    if not (isinstance(proofs, (list, tuple)) and proofs):
        raise Refused("no inclusion proof")
    for proof_bytes in proofs:
        if not isinstance(proof_bytes, bytes):
            raise Refused("proof is not a byte string")
        try:
            fp = io.BytesIO(proof_bytes)
            proof = cbor2.load(fp, str_errors="strict" if checks else "surrogateescape")
            if fp.read(1):
                raise ValueError("trailing bytes after the map")
        except Exception as e:
            raise Refused(f"proof is not valid CBOR: {e}")
        if checks:
            validate_ccf_inclusion_proof(proof)
            if proof[1][2] != STATEMENT_DIGEST:
                raise Refused("data-hash is not the statement digest")
        if not verify_cose(protected_bytes, signature, compute_root(proof), key):
            raise Refused("signature")
    return True


def outcome(path, key, checks=True):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        verify_inclusion_receipt(raw, key, checks)
    except Refused as e:
        return str(e)
    return "verifies"


def check(ok, path, note):
    print(f"{'ok  ' if ok else 'FAIL'} {os.path.relpath(path)}: {note}")
    return not ok


def vectors(root, subdir, pattern):
    paths = sorted(glob.glob(os.path.join(root, subdir, pattern)))
    if not paths:
        sys.exit(f"no vectors matching {subdir}/{pattern} under {root}")
    return paths


def main(root):
    key = read_key(root)
    failures = 0

    for path in vectors(root, "valid", "*.cbor"):
        got = outcome(path, key)
        failures += check(got == "verifies", path, got)

    for path in vectors(root, "invalid", "signature-*.cbor"):
        got, unchecked = outcome(path, key), outcome(path, key, checks=False)
        failures += check(got == "signature" and unchecked == "signature", path,
                          f"{got}; without the checks: {unchecked}")

    for prefix, expected in (("cddl-root-as-leaf-", lambda got: got == "data-hash"),
                             ("utf8-root-as-leaf-", lambda got: got.startswith("proof is not valid CBOR"))):
        for path in vectors(root, "invalid", prefix + "*.cbor"):
            got, unchecked = outcome(path, key), outcome(path, key, checks=False)
            failures += check(expected(got) and unchecked == "verifies", path,
                              f"{got}; without the checks: {unchecked}")

    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))))
