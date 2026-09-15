#!/usr/bin/env python3
"""Check the sample consistency proofs against the draft's verification algorithm.

Roots are recomputed from the leaf derivation in manifest.json rather than read
from it, so the vectors are checked independently of the tool that produced them.
CDDL conformance is checked separately by validate-cbor-examples.sh.

  pip install cbor2
  python3 verify.py [samples/consistency-proofs]
"""
import hashlib
import json
import os
import sys

import cbor2


def H(data):
    return hashlib.sha256(data).digest()


def leaf(i):
    return H(bytes(56) + i.to_bytes(8, "big"))


def mth(lo, hi, cache={}):
    """Merkle Tree Hash of leaves [lo, hi), RFC 9162 shape."""
    if (lo, hi) not in cache:
        if hi - lo == 1:
            cache[lo, hi] = leaf(lo)
        else:
            k = 1
            while 2 * k < hi - lo:
                k *= 2
            cache[lo, hi] = H(mth(lo, lo + k) + mth(lo + k, hi))
    return cache[lo, hi]


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


def load(path):
    with open(path, "rb") as f:
        return cbor2.loads(cbor2.loads(f.read()))


def main(root):
    manifest = json.load(open(os.path.join(root, "manifest.json")))
    failures = 0

    for v in manifest["valid"]:
        older, newer = compute_roots(load(os.path.join(root, "valid", v["file"])))
        ok = older == mth(0, v["m"]) and newer == mth(0, v["n"])
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} valid/{v['file']}")

    for v in manifest["invalid"]:
        if v["expected"] == "cddl":
            continue
        older, newer = compute_roots(load(os.path.join(root, "invalid", v["file"])))
        older_matches = older == mth(0, v["m"])
        newer_matches = newer == mth(0, v["n"])
        if v["expected"] == "older-root-mismatch":
            ok = not older_matches
        elif v["expected"] == "newer-root-mismatch":
            ok = older_matches and not newer_matches
        else:
            ok = False
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} invalid/{v['file']} ({v['expected']})")

    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))))
