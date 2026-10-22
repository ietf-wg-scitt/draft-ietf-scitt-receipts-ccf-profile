---
title: CCF Profile for COSE Receipts
abbrev: CCF Profile for COSE Receipts
docname: draft-ietf-scitt-receipts-ccf-profile-latest
stand_alone: true
ipr: trust200902
area: Security
wg: SCITT
kw: Internet-Draft
cat: std
submissiontype: IETF
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
- name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@ietf.contact
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- name: Antoine Delignat-Lavaud
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: antdl@microsoft.com
  country: UK
- name: Cedric Fournet
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: fournet@microsoft.com
  country: UK
- name: Amaury Chamayou
  organization: Microsoft Research
  street: 21 Station Road
  code: 'CB1 2FB'
  city: Cambridge
  email: amaury.chamayou@microsoft.com
  country: UK

normative:
  RFC8949:
  RFC9162:
  RFC9942: cose-receipts
  RFC9943: scitt-architecture

informative:
  CCF:
    title: "Confidential Consortium Framework"
    target: "https://github.com/microsoft/ccf"

  CCF-Ledger-Format:
    title: "CCF Ledger Format"
    target: "https://microsoft.github.io/CCF/main/architecture/ledger.html"

  CCF-Commit-Evidence:
    title: "CCF Commit Evidence"
    target: "https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#commit-evidence"

  CCF-Receipt-Verification:
    title: "CCF Receipt Verification"
    target: "https://microsoft.github.io/CCF/main/use_apps/verify_tx.html#receipt-verification"

  COIN-FLIPPING:
    title: "Coin Flipping By Telephone - A Protocol For Solving Impossible Problems"
    target: "https://dl.acm.org/doi/epdf/10.1145/1008908.1008911"
    seriesinfo:
      DOI: 10.1145/1323293.1294280

entity:
  SELF: "RFCthis"

--- abstract

This document defines a new verifiable data structure (VDS) type for COSE Receipts and the associated inclusion and consistency proofs, specifically designed for append-only logs produced by the Confidential Consortium Framework (CCF) to provide stronger tamper-evidence guarantees.

--- middle

# Introduction

The COSE Receipts document {{-cose-receipts}} defines a common framework for expressing different types of proofs about verifiable data structures (VDS), providing a standardized way to convey trust-relevant evidence. For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the VDS, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the VDS at a later time.

In this document, we define a new type of VDS and the associated inclusion and consistency proofs for an application of the Confidential Consortium Framework (CCF) ledger that implements the SCITT Architecture defined in {{-scitt-architecture}}. This VDS carries indexed transaction information in a binary Merkle Tree, where new transactions are appended to the right, so that the binary decomposition of the index of a transaction can be interpreted as the position in the tree if 0 represents the left branch and 1 the right branch.
Compared to {{RFC9162}}, the leaves of CCF trees carry additional internal information for the following purposes:

1. To bind the full details of the transaction executed, which is a superset of what is exposed in the proof and captures internal details useful for detailed system audit, but not for application purposes.
1. To allow the distributed system executing the application logic in Trusted Execution Environments (TEEs) to persist signatures to storage early. Receipt production is only enabled once transactions are fully committed by the consensus protocol.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Description of the Confidential Consortium Framework Ledger Verifiable Data Structure

This document defines `CCF_LEDGER_SHA256` for append-only CCF transaction ledgers containing a mix of public and confidential information. These ledgers are integrity-protected by a Merkle Tree and signatures produced via Trusted Execution Environments. The registration request for this verifiable data structure is specified in {{tree-alg-registry}}.

The placeholder `TBD_1` denotes the algorithm identifier, with requested assignment `2`. The CDDL and examples use this requested value pending IANA allocation; it is not an assigned value.

## Merkle Tree Shape {#merkle-tree-shape}

A CCF ledger is a binary Merkle Tree constructed from a hash function H, which is defined from the log type. For instance, the hash function for `CCF_LEDGER_SHA256` is `SHA256`, whose `HASH_SIZE` is 32 bytes.

The Merkle Tree encodes an ordered list of `n` transactions T_n = \{T\[0\], T\[1\], ..., T\[n-1\]\}. Each transaction T\[i\] is serialized to a byte string d\[i\] as defined in {{transaction-components}}, giving the list D_n = \{d\[0\], d\[1\], ..., d\[n-1\]\}. We define the Merkle Tree Hash (MTH) function, which takes as input such a list of serialized transactions, and outputs a single HASH_SIZE byte string called the Merkle root hash, by induction on the list.

This function is defined as follows:

The hash of an empty list is the hash of an empty string:

~~~
MTH({}) = HASH().
~~~
{: #empty-list-merkle-tree-hash title="Merkle Tree Hash of Empty List"}

The hash of a list with one entry (also known as a leaf hash) is:

~~~
MTH({d[0]}) = HASH(d[0]).
~~~
{: #single-entry-merkle-tree-hash title="Merkle Tree Hash of a Single Entry"}

For n > 1, let k be the largest power of two smaller than n (i.e., k < n <= 2k). The Merkle Tree Hash of an n-element list D_n is then defined recursively as:

~~~
MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n])),
~~~
{: #recursive-merkle-tree-hash title="Recursive Merkle Tree Hash"}

where:

- \|\| denotes concatenation
- : denotes concatenation of lists
- D\[k1:k2\] = D'_(k2-k1) denotes the list \{d'\[0\] = d\[k1\], d'\[1\] = d\[k1+1\], ..., d'\[k2-k1-1\] = d\[k2-1\]\} of length (k2 - k1).

## Transaction Components {#transaction-components}

Each leaf in a CCF ledger carries the following components:

~~~ cddl
ccf-leaf = [
  ; Byte string of size HASH_SIZE(32)
  internal-transaction-hash: bstr .size 32

  ; Text string of at most 1024 bytes
  internal-evidence: tstr .size (1..1024)

  ; Byte string of size HASH_SIZE(32)
  data-hash: bstr .size 32
]
~~~
{: #ccf-leaf-cddl title="CCF Leaf CDDL"}

The `ccf-leaf` array is the representation of these components in an inclusion proof ({{ccf-inclusion-proofs}}). It is not what is hashed into the tree. The serialized transaction d\[i\] that is input to MTH in {{merkle-tree-shape}} is the byte string of length 3 * HASH_SIZE obtained by concatenating the internal transaction hash, the hash of the internal evidence, and the data hash:

~~~
d[i] = internal-transaction-hash
       || HASH(internal-evidence)
       || data-hash
~~~
{: #transaction-serialization title="Transaction Serialization"}

where HASH(internal-evidence) is the digest of the UTF-8 encoding of the `internal-evidence` text string. The leaf hash MTH(\{d\[i\]\}) = HASH(d\[i\]) is therefore HASH(internal-transaction-hash \|\| HASH(internal-evidence) \|\| data-hash), which is the value computed by the first step of `compute_root` in {{ccf-inclusion-receipt-verification}}. Note that the proof carries `internal-evidence` itself rather than its digest: revealing the evidence is what demonstrates that the transaction was committed (see below).

The `internal-transaction-hash` and `internal-evidence` values are internal to the CCF implementation. They can be safely ignored by receipt Verifiers, but they commit the transparency service (TS) to the whole tree contents and may be used for additional, CCF-specific auditing.

`internal-transaction-hash` is a hash over the complete entry in the {{CCF-Ledger-Format}}, and `internal-evidence` is a revealable {{CCF-Commit-Evidence}} value that allows early persistence of ledger entries before distributed consensus can be established. This mechanism is useful to implement high-throughput transparency applications in Trusted Execution Environments (TEEs) that only provide a limited amount of memory, while maintaining high availability afforded by distributed consensus. Using a secure one-way function `f` to publish an `f(x)` commitment to an `x` value that can be revealed at a later time is a common feature of distributed protocols ({{COIN-FLIPPING}}). The hash function used for `internal-transaction-hash` is the same hash function `H` as in the Merkle Tree construction for the selected verifiable data structure algorithm. For `CCF_LEDGER_SHA256`, this function is `SHA256`.

`data-hash` is the hash of the bytes of the Signed Statement as registered: the `COSE_Sign1` encoding with CBOR tag 18 retained ({{Section 6.1 of -scitt-architecture}}) and an empty unprotected header map ({{Section 6.3 of -scitt-architecture}}), other elements as submitted. The hash function used for `data-hash` is also the same hash function `H` as in the Merkle Tree construction for the selected verifiable data structure algorithm. For `CCF_LEDGER_SHA256`, this function is `SHA256`.

`data-hash` captures the Signed Statement, not the Transparent Statement of {{Section 7 of -scitt-architecture}}, which adds Receipts to that unprotected header. A Verifier holding a Transparent Statement recovers the preimage as follows:

1. Take the `COSE_Sign1` of the Transparent Statement.
1. Replace its unprotected header with an empty map ({{Section 6.3 of -scitt-architecture}}).
1. Keep tag 18, and keep the encoded values of the protected header, payload and signature as received.
1. Hash the resulting byte string with `H` (`SHA256` for `CCF_LEDGER_SHA256`).


# CCF Inclusion Proofs {#ccf-inclusion-proofs}

CCF inclusion proofs consist of a list of digests tagged with a single left-or-right bit.

~~~ cddl
ccf-proof-element = [
  ; Position of the element
  left: bool

  ; Hash of the proof element: byte string of size HASH_SIZE(32)
  hash: bstr .size 32
]

ccf-inclusion-proof = bstr .cbor {
  &(leaf: 1) => ccf-leaf
  &(path: 2) => [* ccf-proof-element]
}
~~~
{: #ccf-inclusion-proof-cddl title="CCF Inclusion Proof CDDL"}

Unlike some other tree algorithms, neither the index of the element nor the size of the tree is explicit in the inclusion proof. Read from the leaf up, the left-or-right bits are the binary decomposition of the index for the first `k` elements, where `k` is the largest power of two not greater than the tree size; for later elements the proof may have fewer elements than the depth of the index, and the index cannot be read from the proof alone. The `path` is empty for a tree of size 1, whose root is the leaf hash.

## CCF Inclusion Proof Signature {#ccf-inclusion-proof-signature}

The proof signature for a CCF inclusion proof is a COSE signature (encoded with the `COSE_Sign1` CBOR type) which includes the following additional requirements for protected and unprotected headers. These follow the conventions of {{Section 5.2.1 of -cose-receipts}}; the corresponding CDDL is given in {{receipt-usage}}. Please note that there may be additional header parameters defined by the application.

The protected header parameters for the CCF inclusion proof signature MUST include the following:

* `vds` (label 395): `int`. This header MUST be set to the verifiable data structure algorithm identifier for `CCF_LEDGER_SHA256` (`TBD_1`).

The unprotected header for a CCF inclusion proof signature MUST include the following:

* `vdp` (label 396): map. This header conveys the verifiable data structure proofs, keyed by proof type. It MUST contain the `inclusion-proof` (-1) key, whose value is an array of one or more `ccf-inclusion-proof` values as defined above. The proof type is identified solely by this key; no other header parameter is used to convey it.

The payload of the signature is the CCF ledger Merkle root digest, and MUST be detached in order to force verifiers to recompute the root from the inclusion proofs in the unprotected header. This provides a safeguard against implementation errors that use the payload of the signature but do not recompute the root from the inclusion proof. When the array contains more than one inclusion proof, every proof MUST compute to the same root.

## Inclusion Proof Verification Algorithm

After decoding each `ccf-inclusion-proof` byte string, the Verifier MUST validate that the decoded value is well constructed with regard to the schema defined in {{ccf-inclusion-proof-cddl}}, including {{ccf-leaf-cddl}} for the leaf, and MUST reject the proof before `compute_root` is called if any check fails. In particular:

* the byte string is valid CBOR ({{Section 5.3.1 of RFC8949}}), in particular the map has no duplicate keys;
* the map has the keys `leaf` (1) and `path` (2);
* `internal-transaction-hash` is a byte string of exactly HASH_SIZE (32) bytes;
* `internal-evidence` is a text string of 1 to 1024 bytes of valid UTF-8;
* `data-hash` is a byte string of exactly HASH_SIZE (32) bytes;
* `path` is an array, each element of which is an array of exactly two items: a boolean and a byte string of exactly HASH_SIZE (32) bytes.

Without these checks, since leaf and interior node hashes are not domain separated, an oversized path element lets an existing leaf be recomputed as if it were an interior node, so that a proof for a leaf and `data-hash` of the attacker's choosing still recomputes a validly signed root (a second-preimage-style forgery).

CCF uses the following algorithm to verify an inclusion receipt:

~~~
compute_root(proof):
  h := HASH(
       proof.leaf.internal-transaction-hash
           || HASH(proof.leaf.internal-evidence)
           || proof.leaf.data-hash
       )

  for [left, hash] in proof.path:
      h := HASH(hash || h) if left
           HASH(h || hash) else
  return h

verify_inclusion_receipt(inclusion_receipt, statement_digest):
  assert(VDP_LABEL in inclusion_receipt.unprotected_header)
  let vdp = inclusion_receipt.unprotected_header[VDP_LABEL]
  assert(INCLUSION_PROOF_LABEL in vdp)
  let proofs = vdp[INCLUSION_PROOF_LABEL]
  assert(len(proofs) > 0)
  assert(inclusion_receipt.payload == nil)

  for proof in proofs:
      assert(validate_ccf_inclusion_proof(proof))
      assert(proof.leaf.data-hash == statement_digest)
      # Use the Merkle Root as the detached payload
      let payload = compute_root(proof)
      assert(verify_cose(inclusion_receipt, payload))
  return true
~~~
{: #ccf-inclusion-receipt-verification title="CCF Inclusion Receipt Verification"}

`VDP_LABEL` is the `vdp` header parameter label (396) and `INCLUSION_PROOF_LABEL` is the `inclusion-proof` proof type label (-1), both defined by {{-cose-receipts}}. Each element of `proofs` is a `ccf-inclusion-proof`, i.e., a byte string wrapping a CBOR-encoded map, which is decoded and validated against the schema defined in {{ccf-inclusion-proof-cddl}} before `compute_root` is applied.

`statement_digest` is the `data-hash` of the candidate Signed Statement, computed by the Verifier from the bytes of that Signed Statement as described in {{transaction-components}}; it MUST NOT be taken from the receipt. Every proof in the receipt MUST have a `data-hash` equal to `statement_digest`. This defines how the inclusion proofs of this profile are consumed ({{Section 4.4.1 of -cose-receipts}}), by applying them to the bytes of a candidate entry ({{Section 5.2.1 of -cose-receipts}}). If the receipt also carries consistency proofs, they MUST recompute the same root ({{receipt-usage}}).

A description can also be found at {{CCF-Receipt-Verification}}.

# CCF Consistency Proofs {#ccf-consistency-proofs}

A CCF consistency proof establishes that the tree of `m` transactions with root `R_m` is a prefix of the tree of `n` transactions with root `R_n`, where `0 < m < n`: every transaction of the older tree is at the same position in the newer tree.

~~~ cddl
ccf-consistency-proof = bstr .cbor {
  ; Root of the largest complete subtree containing
  ; the last transaction of the older tree
  &(anchor: 1) => bstr .size 32

  ; Siblings from the anchor to the newer root
  &(path: 2) => [+ ccf-proof-element]
}
~~~
{: #ccf-consistency-proof-cddl title="CCF Consistency Proof CDDL"}

The `anchor` MUST be the root of the subtree covering transactions `T[m - 2^t], ..., T[m - 1]`, where `2^t` is the largest power of two dividing `m`; when `m` is a power of two, the anchor is `R_m`. The `path` lists the sibling of each node on the path from the anchor to `R_n`, tagged as in inclusion proofs. Left siblings belong to both trees and right siblings only to the newer one, so folding the anchor with the left siblings alone yields `R_m`, and with all siblings `R_n`. Apart from the tags, `path` holds the digests of the same subtrees, in the same order, as the consistency proof of {{Section 2.1.4.1 of RFC9162}} for the same sizes, with the anchor as the first element of that proof when `m` is not a power of two. The digests themselves are those of the Merkle Tree Hash of {{merkle-tree-shape}}, not of {{RFC9162}}, which prefixes leaves and nodes differently.

The first element of `path` MUST be a right sibling (`left` is `false`): the anchor is the root of the last complete subtree of the older tree, so its first sibling can only hold transactions appended after `T[m - 1]`. A proof whose first element is a left sibling MUST be rejected. In particular, there is no consistency proof for `m == n`, for which every sibling would be a left one.

Neither tree size is carried by the proof, and verification does not establish `m`, `n`, or that the anchor is the node required above. What verification establishes is that every transaction of the tree with root `R_m` is at the same position in the tree with root `R_n` ({{consistency-receipts-security}}); the anchor requirement fixes a canonical encoding of that fact.

## CCF Consistency Proof Signature

The proof signature for a CCF consistency proof is a `COSE_Sign1` with the same protected header requirements as an inclusion proof signature ({{ccf-inclusion-proof-signature}}). Its unprotected header MUST include:

* `vdp` (label 396): map. It MUST contain the `consistency-proof` (-2) key, whose value is an array of one or more `ccf-consistency-proof` values, each relating one older root to the newer root.

The payload is the newer root `R_n`, and MUST be detached. When the array contains more than one consistency proof, every proof MUST compute to the same newer root, and a Verifier MUST reject the receipt if any proof computes to a different one. The older root `R_m` is not carried by the receipt: the verifier already holds it, typically as the root recomputed from an inclusion receipt ({{ccf-inclusion-receipt-verification}}), and checks that at least one proof recomputes it. Other proofs in the same array may start from other older roots.

## Consistency Proof Verification Algorithm

Before applying this algorithm, the Verifier MUST have validated the `vdp` map as required in {{receipt-usage}}. After decoding each `ccf-consistency-proof` byte string, the Verifier MUST validate that the decoded value is well constructed with regard to the schema defined in {{ccf-consistency-proof-cddl}}, and MUST reject the proof before `compute_roots` is called if any check fails. In particular:

* the byte string is valid CBOR ({{Section 5.3.1 of RFC8949}}), in particular the map has no duplicate keys;
* the map has the keys `anchor` (1) and `path` (2);
* `anchor` is a byte string of exactly HASH_SIZE (32) bytes;
* `path` is a non-empty array, each element of which is an array of exactly two items: a boolean and a byte string of exactly HASH_SIZE (32) bytes.

These checks ensure that `compute_roots` is only applied to well-formed proofs.

A consistency receipt is verified against a trusted `older_root` as follows:

~~~
compute_roots(proof):
  older := proof.anchor
  newer := proof.anchor

  for [left, hash] in proof.path:
      if left:
          older := HASH(hash || older)
          newer := HASH(hash || newer)
      else:
          newer := HASH(newer || hash)
  return older, newer

verify_consistency_receipt(consistency_receipt, older_root):
  assert(VDP_LABEL in consistency_receipt.unprotected_header)
  let vdp = consistency_receipt.unprotected_header[VDP_LABEL]
  assert(CONSISTENCY_PROOF_LABEL in vdp)
  let proofs = vdp[CONSISTENCY_PROOF_LABEL]
  assert(len(proofs) > 0)
  assert(consistency_receipt.payload == nil)

  let payload = nil
  let older_root_found = false
  for proof in proofs:
      assert(validate_ccf_consistency_proof(proof))
      # The first sibling of the anchor is in the newer tree only
      assert(proof.path[0].left == false)
      let older, newer = compute_roots(proof)
      # Every proof must compute to the same newer root
      assert(payload == nil or newer == payload)
      payload := newer
      if older == older_root:
          older_root_found := true
  # At least one proof must start from older_root
  assert(older_root_found)

  # Use the common newer Merkle Root as the detached payload
  assert(verify_cose(consistency_receipt, payload))
  return true
~~~
{: #ccf-consistency-receipt-verification title="CCF Consistency Receipt Verification"}

`CONSISTENCY_PROOF_LABEL` is the `consistency-proof` proof type label (-2) defined by {{-cose-receipts}}. Each element of `proofs` is a `ccf-consistency-proof`, i.e., a byte string wrapping a CBOR-encoded map, which is decoded and validated against the schema defined in {{ccf-consistency-proof-cddl}} before `compute_roots` is applied. All proofs are folded before the signature is checked, so that a receipt in which any proof computes to a different newer root is rejected, whichever proof the Verifier is interested in. If the receipt also carries inclusion proofs, they MUST recompute the same root ({{receipt-usage}}). The comparison with `older_root` binds the receipt to a state the verifier already trusts: a receipt in which no proof recomputes `older_root` proves nothing about that state. It also confirms that the anchor is a node of that state, but not that it is the anchor required in {{ccf-consistency-proofs}}, which is not needed for the guarantee the receipt provides ({{consistency-receipts-security}}).

The signature attests that `payload` is the root of a state of the ledger; verification establishes that the state with root `older_root` is a prefix of it, not that the signed value is itself a Merkle Tree Hash of {{merkle-tree-shape}} ({{consistency-receipts-security}}).

# Usage in COSE Receipts {#receipt-usage}

A COSE Receipt with CCF inclusion or consistency proofs is described by the following CDDL definition, which follows {{Section 5.2.1 of -cose-receipts}} and {{Section 5.3.1 of -cose-receipts}}:

~~~ cddl
protected-header-map = {
  &(alg: 1) => int
  &(vds: 395) => TBD_1
  * cose-label => cose-value
}

TBD_1 = 2 ; Requested assignment for CCF_LEDGER_SHA256
~~~
{: #protected-header-map-cddl title="Protected Header Map CDDL"}

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. Verifiable data structure algorithm identifier. Value type: int.

The unprotected header is described by the following CDDL definition:

~~~ cddl
inclusion-proof = ccf-inclusion-proof
inclusion-proofs = [ + inclusion-proof ]

consistency-proof = ccf-consistency-proof
consistency-proofs = [ + consistency-proof ]

verifiable-proofs = {
  &(inclusion-proof: -1) => inclusion-proofs
  ? &(consistency-proof: -2) => consistency-proofs
  //
  &(consistency-proof: -2) => consistency-proofs
}

unprotected-header-map = {
  &(vdp: 396) => verifiable-proofs
  * cose-label => cose-value
}
~~~
{: #unprotected-header-map-cddl title="Unprotected Header Map CDDL"}

- vdp (label: 396): REQUIRED. Verifiable data structure proofs. Value type: map.
- inclusion-proof (label: -1): Inclusion proofs. Value type: array of `ccf-inclusion-proof`.
- consistency-proof (label: -2): Consistency proofs. Value type: array of `ccf-consistency-proof`.

At least one of `inclusion-proof` and `consistency-proof` MUST be present. All proofs in a receipt, of either type, MUST recompute the same root (the newer root, for consistency proofs), which is the detached payload. A Verifier MUST reject a receipt in which any proof present in the `vdp` map recomputes a different root, including proofs of a type it does not otherwise use: the `vdp` map is in the unprotected header, so proofs can be added to a receipt without invalidating its signature. The proof type is conveyed by the key of the `vdp` map, as specified by {{-cose-receipts}}; it is not carried in a separate header parameter. A Verifier MUST reject a receipt whose `vdp` map is not valid CBOR ({{Section 5.3.1 of RFC8949}}) or does not match `verifiable-proofs` in {{unprotected-header-map-cddl}}, before applying either verification algorithm.

# Privacy Considerations

See the privacy considerations section of:

*  {{-cose-receipts}}

# Security Considerations

The security considerations of {{-cose-receipts}} apply.

## Trusted Execution Environments {#trusted-execution-environments}

CCF networks of nodes rely on executing in TEEs to secure their function, in particular:

1. The evaluation of registration policies
2. The creation and usage of receipt signing keys

A compromise in the TEE platform used to execute the network may allow an attacker to produce invalid and divergent ledger branches.
Clients can mitigate this risk in two ways: by regularly auditing the consistency of the CCF ledger, for instance by verifying consistency receipts ({{ccf-consistency-receipt-verification}}) from roots they hold to the current root; and by regularly fetching attestation information about the TEE instances, available in the ledger and from the network itself, and confirming that the nodes composing the network are running up-to-date, trusted platform components.

## Operators {#operators}

An operator has the ability to start successor networks with a distinct identity. The operator of a CCF network can recover the service by starting a successor network, for example a new CCF network with its own service identity, that endorses the ledger state of the previous instance. This provides service continuity after a catastrophic failure of a majority of the nodes. However, a malicious operator could exploit this mechanism and truncate the ledger’s history by initializing the successor network from an earlier ledger prefix, thereby omitting some later entries. Clients can mitigate this risk by auditing the successor ledger and verifying that their latest known receipts from the prior service are included in the successor’s ledger.

## Consistency Receipts {#consistency-receipts-security}

A consistency receipt relates two roots and establishes nothing about ledger contents on its own. Verifiers MUST compare the recomputed older root with a root they have already verified; which signing key they accept, including that of a successor network ({{operators}}), is their trust policy as for any Receipt of {{-cose-receipts}}. Consistency receipts also cannot provide guarantees about the correct application of Registration Policies, which requires additional material as outlined in {{Section 5.1.1.2 of -scitt-architecture}}.

The receipt carries no tree sizes and the signature covers only the newer root, so sizes cannot be authenticated; none is needed. Because the older root is trusted and the newer root is signed, every node a passing proof folds is, barring a second preimage of `H`, a node of one of the two states, and every transaction of the older state is at the same position in the signed one. This holds whether or not the anchor is the canonical node of {{ccf-consistency-proofs}}.

Verification does not establish that the signed value is itself a Merkle Tree Hash of {{merkle-tree-shape}}; that is attested by the Transparency Service, and a Transparency Service signing values that are not roots of its ledger is the misbehaviour addressed in {{trusted-execution-environments}} and {{operators}}. A Verifier that needs `m` or `n` MUST obtain them from a source it trusts independently of the receipt; this document does not define one.

# IANA Considerations

## Additions to Existing Registries

The registries in this section are defined by {{-cose-receipts}}.

### COSE Verifiable Data Structure Algorithms {#tree-alg-registry}

This document requests IANA to add the following new value to the "COSE Verifiable Data Structure Algorithms" registry:

* Name: CCF_LEDGER_SHA256
* Value: TBD_1 (requested assignment 2)
* Description: Append-only CCF transaction ledgers protected by SHA-256 Merkle Trees and signatures produced via Trusted Execution Environments.
* Reference: {{&SELF}}
* Change Controller: IETF

### COSE Verifiable Data Structure Proofs {#tree-proof-registry}

This document requests IANA to add the following new entries to the "COSE Verifiable Data Structure Proofs" registry:

* Verifiable Data Structure: TBD_1 (requested assignment 2)
* Name: inclusion proofs
* Label: -1
* CBOR Type: array (of bstr)
* Description: Proof of inclusion
* Reference: {{&SELF}}, {{ccf-inclusion-proofs}} and {{receipt-usage}}
* Change Controller: IETF

and:

* Verifiable Data Structure: TBD_1 (requested assignment 2)
* Name: consistency proofs
* Label: -2
* CBOR Type: array (of bstr)
* Description: Proof of consistency
* Reference: {{&SELF}}, {{ccf-consistency-proofs}} and {{receipt-usage}}
* Change Controller: IETF

--- back
