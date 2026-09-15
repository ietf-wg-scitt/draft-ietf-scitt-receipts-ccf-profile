#!/usr/bin/env python3
"""Check the sample consistency proofs against the draft's verification algorithm.

Every vector comes from one tree whose leaves are derived below, so R_m and R_n
are recomputed here rather than trusted from the tool that produced the vectors.
Valid vectors are named NN-<case>-<m>-<n>.cbor. Tampered vectors derive from
11-doc-example-23-68 and are named by the check that catches them:
older-root-* must not fold to R_23; newer-root-* must fold to R_23 but not to
R_68. cddl-* vectors are checked by validate-cbor-examples.sh, not here.

  pip install cbor2
  python3 verify.py [samples/consistency-proofs]
"""
import glob
import hashlib
import os
import re
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


def check(ok, path):
    print(f"{'ok  ' if ok else 'FAIL'} {os.path.relpath(path)}")
    return not ok


def vectors(root, subdir, pattern):
    paths = sorted(glob.glob(os.path.join(root, subdir, pattern)))
    if not paths:
        sys.exit(f"no vectors matching {subdir}/{pattern} under {root}")
    return paths


def main(root):
    failures = 0

    for path in vectors(root, "valid", "*.cbor"):
        m, n = map(int, re.search(r"-(\d+)-(\d+)\.cbor$", path).groups())
        older, newer = compute_roots(load(path))
        failures += check(older == mth(0, m) and newer == mth(0, n), path)

    r23, r68 = mth(0, 23), mth(0, 68)
    for path in vectors(root, "invalid", "older-root-*.cbor"):
        older, _ = compute_roots(load(path))
        failures += check(older != r23, path)
    for path in vectors(root, "invalid", "newer-root-*.cbor"):
        older, newer = compute_roots(load(path))
        failures += check(older == r23 and newer != r68, path)

    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))))
