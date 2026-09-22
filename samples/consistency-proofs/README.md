# Sample CCF consistency proofs

Test vectors for `ccf-consistency-proof`. Each `.cbor` file is one proof value, a CBOR byte string wrapping the map, exactly what goes into a receipt's `vdp[-2]` array. No signed consistency receipt exists yet, so there is no receipt-level sample.

The valid vectors were produced by [merklecpp](https://github.com/microsoft/merklecpp) (`merkle::tiles::ProofEngine::consistency_proof`) over one tree of 70,000 leaves and re-tagged into the draft's shape:

```
leaf(i) = SHA-256(56 zero bytes || uint64 big-endian i)
node    = SHA-256(left || right)
```

## Files

| Path | Contents |
|---|---|
| `valid/NN-<case>-<m>-<n>.cbor` | 15 proofs that the tree of `m` leaves is a prefix of the tree of `n` leaves |
| `invalid/cddl-<case>.cbor` | 15 vectors that do not conform to the CDDL |
| `invalid/older-root-<case>.cbor` | 5 tampered vectors whose recomputed older root differs from `R_m` |
| `invalid/newer-root-<case>.cbor` | 3 tampered vectors whose older root still matches but whose newer root differs from `R_n` |
| `invalid/anchor-<case>-<m>-<n>.cbor` | 1 vector that folds to `(R_m, R_n)` but whose anchor is not the one the draft requires |
| `verify.py` | Recomputes `R_m` and `R_n` from the leaf derivation and checks every non-`cddl-` vector |

## Checks

`validate-cbor-examples.sh` in the parent directory runs both in CI:

- CDDL: every `valid/*.cbor` and every other `invalid/*.cbor` conforms to `ccf-consistency-proof` as extracted from the draft; every `invalid/cddl-*.cbor` does not.
- Roots: `verify.py` applies the draft's `compute_roots` to each vector. Valid vectors must yield `(R_m, R_n)` and use the anchor required by the draft; `older-root-*` must not yield `R_m`; `newer-root-*` must yield `R_m` but not `R_n`; `anchor-*` must yield `(R_m, R_n)` from a different anchor.


## Valid cases

Tags read anchor → root; `R` is a right sibling (newer tree only), `L` a left sibling (shared by both trees).

| # | m → n | Tags | Exercises |
|---|---|---|---|
| 01 | 1 → 2 | `R` | Smallest proof; anchor = older root = first leaf |
| 02 | 4 → 5 | `R` | Perfect older tree; right sibling is a bare leaf off the root |
| 03 | 4 → 8 | `R` | Both trees perfect |
| 04 | 4 → 6 | `R` | Perfect older tree, truncated right sibling `[4,6)` |
| 05 | 5 → 6 | `RL` | Adjacent sizes; a pass-through level; same tags as 06 |
| 06 | 6 → 8 | `RL` | Anchor is a 2-leaf subtree `[4,6)`; same tags as 05 |
| 07 | 7 → 8 | `RLL` | Older tree one short of perfect; every level has a sibling |
| 08 | 12 → 13 | `RL` | Anchor `[8,12)` (height 2) with a bare-leaf sibling |
| 09 | 64 → 70 | `R` | merklecpp docs example 1 |
| 10 | 23 → 68 | `RLLRLRR` | merklecpp docs example 2; base for the tampered vectors |
| 11 | 37 → 45 | `RRLRL` | Truncated right sibling `[40,45)` mid-path |
| 12 | 100 → 1000 | `RRRLLRRR` | Anchor `[96,100)`, large gap |
| 13 | 3 → 65536 | `RL` + 14×`R` | Tiny older tree inside a perfect 2^16 tree |
| 14 | 1 → 70000 | 17×`R` | Longest path in the set |
| 15 | 69999 → 70000 | `R` + 8×`L` | Adjacent sizes at the top; mostly shared siblings |

Cases 05, 06 and 08 share the tag string `RL`: the tags do not determine the tree sizes, which is why none are carried.

## Invalid cases

The tampered vectors derive from case 10 (23 → 68); the anchor vector is constructed.

| File | Tampering |
|---|---|
| `older-root-flipped-tag-first-element` | First element re-tagged as left |
| `older-root-flipped-tag-left-to-right` | A shared left sibling re-tagged as right |
| `older-root-reversed-path` | Elements listed root → anchor |
| `older-root-zeroed-anchor` | Anchor replaced by zeros |
| `older-root-zeroed-left-sibling` | A shared left sibling replaced by zeros |
| `newer-root-extended-path` | Extra right sibling appended |
| `newer-root-truncated-path` | Last element dropped: this is the valid proof 23 → 64, caught only by the signature over the detached payload |
| `newer-root-zeroed-right-sibling` | A newer-only right sibling replaced by zeros |
| `anchor-noncanonical-8-12` | 8 → 12 with anchor `[4,8)` and its shared sibling `[0,4)` prepended to the path (`LR`): folds to `R_8` and `R_12`, but the anchor of a proof from 8 MUST be `R_8`; a verifier can only tell if it knows `m` |
| `cddl-anchor-31-bytes`, `cddl-anchor-33-bytes`, `cddl-anchor-text` | Anchor of the wrong size or type |
| `cddl-element-hash-33-bytes`, `cddl-element-three-items`, `cddl-element-as-map`, `cddl-left-not-bool` | Malformed path element |
| `cddl-missing-anchor`, `cddl-missing-path`, `cddl-empty-path` | Missing or empty required key |
| `cddl-unknown-key-3`, `cddl-text-keys`, `cddl-array-not-map` | Wrong map shape (the map is closed) |
| `cddl-not-bstr-wrapped`, `cddl-double-bstr-wrapped` | Wrong `bstr .cbor` wrapping |
