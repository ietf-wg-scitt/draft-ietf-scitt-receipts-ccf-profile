# Sample CCF inclusion receipts with an empty path

Test vectors for inclusion receipts whose proof has an empty `path`, which the draft allows for a tree of size 1. Each `.cbor` file is one receipt, a tagged `COSE_Sign1` (`CCF_Receipt` in `../cose-receipt.cddl`) with one `ccf-inclusion-proof` in `vdp[-1]`.

All receipts are signed with deterministic ECDSA (RFC 6979) under one fixed test key, whose public key is in `keys.cbor` (a COSE_KeySet with one P-384 key, kid `sonde-kid-1`; the receipts name ES384 in their protected header). Every receipt is checked against the statement digest `SHA-256("statement")` = `b111c6e1d318f203063e5c16bab43c108326af0aa2f7b65760c95547a43dbe52`; no Signed Statement is included.

The leaves:

```
L = [ internal-transaction-hash: SHA-256("its"),
      internal-evidence:         "ce:2.5:" followed by 64 "a",
      data-hash:                 SHA-256("statement") ]
```

The `root-as-leaf` vectors take a tree of two leaves, `L` on the left and a leaf `R` on the right, and write its root as a leaf with an empty path:

```
internal-transaction-hash = HASH(d(L))          the left child
internal-evidence         = d(R)                the 96-byte serialization of R
data-hash                 = empty (in signature-*: the statement digest, 32 bytes)
```

Here d is the serialization of Transaction Components. For the two vectors with an empty data-hash, the unchecked leaf calculation gives HASH(HASH(d(L)) || HASH(d(R))), the original two-leaf root. The signature-* vector instead appends the expected 32-byte statement digest, giving a different root. Leaf and node hashes are not domain separated. The empty-data-hash vectors violate the leaf schema and do not match the expected statement digest; the signature-* vector fails signature verification.

## Files

| Path | Expected | Refused by | Draft section |
|---|---|---|---|
| `valid/01-one-leaf-empty-path.cbor` | verifies, root `07a9c2f9dc15fedb52f83d2fc35d375e4b6720ffad9e389cc711de307802ce3a` | | 3, "The `path` is empty for a tree of size 1, whose root is the leaf hash"; 2.1, MTH of one entry |
| `invalid/cddl-root-as-leaf-empty-data-hash.cbor` | rejected | `data-hash` is not 32 bytes | 2.2, `ccf-leaf`; 3.2, the `data-hash` check and `data-hash == statement_digest` |
| `invalid/signature-root-as-leaf-data-hash-32.cbor` | rejected | the signature, because the root is another | 3.2, `verify_cose` over `compute_root` |
| `invalid/utf8-root-as-leaf-evidence-not-utf8.cbor` | rejected | the proof is not valid CBOR: `internal-evidence` is a text string that is not valid UTF-8; its `data-hash` is empty too | 3.2, the first and the `internal-evidence` checks; RFC 8949 Section 5.3.1 |

keys.cbor holds the public test key. verify.py adapts the draft's inclusion-verification pseudocode for these fixed fixtures. Every root-as-leaf fixture is also checked with proof validation and the statement-digest comparison disabled. The two empty-data-hash fixtures must then verify, while the signature-* fixture must still fail signature verification. This is a fixture checker, not a complete profile verifier.

The right leaf `R`:

- `cddl-*` and `signature-*`: R uses the 32 ASCII bytes internal-transaction-hash-000001 as internal-transaction-hash, the text ce:2.5:51654972 as internal-evidence, and the 32 ASCII bytes data-hash-of-a-statement-0000001 as data-hash. The SHA-256 digest of the UTF-8 encoding of ce:2.5:51654972 is valid UTF-8, so the complete 96-byte d(R) is valid UTF-8. For cddl-*, the empty data-hash fails the size check and also differs from the expected statement digest. The signed root is `28a11a835421faebbf4addb5623ad27dca5753798d52182c6f8d0d234577def8`.
- `utf8-*`: R uses the SHA-256 digest of the ASCII bytes its as internal-transaction-hash, the text ce:2.5: followed by 64 lowercase b characters as internal-evidence, and the SHA-256 digest of the ASCII bytes statement as data-hash. For this particular choice of R, the 96-byte d(R) is not valid UTF-8. This does not imply that every serialization made from hash outputs is invalid UTF-8. The signed root is `7d78bec57d533d3192f1047b1b47cf6042a37be62cd5fcfa6dc88bb1e52e4cf4`.

## Checks

`validate-cbor-examples.sh` in the parent directory runs both in CI:

- CDDL: `valid/*.cbor` and `invalid/signature-*.cbor` conform to `CCF_Receipt` as extracted from the draft; `invalid/cddl-*.cbor` and `invalid/utf8-*.cbor` do not, both for their empty `data-hash`. The `cddl` tool (0.12.14) accepts a text string that is not valid UTF-8, so the CDDL step alone does not catch the `utf8-*` case.
- Verification: `verify.py` needs `cbor2` and `cryptography`. The valid vector must verify; `signature-*` must fail on the signature, with and without the checks; `cddl-*` must fail on the size check of `data-hash` and `utf8-*` on decoding, and both must verify when read without the checks and without the comparison with the statement digest, which shows that these checks are what refuses them. `verify.py` does not look for duplicate map keys; none of these vectors has one.
