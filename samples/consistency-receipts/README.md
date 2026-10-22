# Sample CCF consistency receipts

Test vectors for the receipt-level checks of `verify_consistency_receipt` (Figure 9) that the consistency proof samples in `../consistency-proofs` do not exercise, because no proof there is signed. Each `.cbor` file is one consistency receipt, a tagged `COSE_Sign1` (`CCF_Receipt` in `../cose-receipt.cddl`) with its `ccf-consistency-proof` values in `vdp[-2]` and a detached payload. `older-roots.json` gives the older root each receipt is checked against.

All four are signed with deterministic ECDSA (RFC 6979) under a fixed P-384 test key. `keys.cbor` holds its public key as a COSE_KeySet with one key, kid `sonde-kid-1`, and the receipts name ES384 in their protected header. The signed payload is the newer root `R_24`.

The proofs come from one ledger of a local scitt-ccf-ledger instance (commit `00101f769d872711356e080fbb089ac48589c60a`, CCF 7.0.17, virtual mode, one node) with signed states at tree sizes 19, 22 and 24, computed from its leaves. That service signed `R_24`; the receipts here carry the test key's signature over the same root instead.

## Files

Tags read anchor to root; `R` is a right sibling, `L` a left one.

| Path | Proofs | Older root | Expected | Refused by |
|---|---|---|---|---|
| `invalid/newer-root-second-proof-anchor-bit-flipped.cbor` | 19 to 24 (`RLRL`), and the 22-to-24 proof (`RLL`) with one anchor bit flipped, which computes another newer root | `R_19` | rejected | `assert(payload == nil or newer == payload)` |
| `invalid/newer-root-second-proof-other-roots.cbor` | 19 to 24 (`RLRL`), and the proof from `R_20` to `R_22` of the same ledger (`RL`) | `R_19` | rejected | `assert(payload == nil or newer == payload)` |
| `invalid/first-sibling-unchanged-tree-24-24.cbor` | 24 to 24: the anchor is the subtree of leaves 16 to 23 and its one sibling the left subtree of leaves 0 to 15 (`L`); both folds give `R_24` | `R_24` | rejected | `assert(proof.path[0].left == false)` |
| `invalid/first-sibling-deeper-anchor-22-24.cbor` | 22 to 24 from leaf 21, below the anchor that Section 4 requires for 22, the subtree of leaves 20 and 21 (`LRLL`); it folds to `R_22` and `R_24` | `R_22` | rejected | `assert(proof.path[0].left == false)` |

Under the Figure 9 of `draft-ietf-scitt-receipts-ccf-profile-05`, all four verify: the first two because only proofs that start from `older_root` were folded into the payload, the last two because no first-sibling check existed.

## Checks

`validate-cbor-examples.sh` in the parent directory runs both in CI:

- CDDL: every receipt conforms to `CCF_Receipt` as extracted from the draft.
- Verification: verify.py needs cbor2 and cryptography. Each receipt must fail its named check. In a diagnostic run, that check is disabled and the first computed newer root is retained as the signature payload; the receipt must then verify. Retaining the first root is equivalent to Figure 9 while the common-root check is enabled. Figure 9 itself assigns the payload on every iteration, so the diagnostic run is not a literal single-line deletion from that algorithm. This is a fixture checker, not a complete profile verifier: it reads the protected header as one CBOR map but does not check its parameters, and it does not look for duplicate map keys.
