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
  RFC9162:
  I-D.ietf-cose-merkle-tree-proofs: cose-receipts
  I-D.ietf-scitt-architecture: scitt-architecture

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

This document defines a new verifiable data structure (VDS) type for COSE Receipts and inclusion proofs specifically designed for append-only logs produced by the Confidential Consortium Framework (CCF) to provide stronger tamper-evidence guarantees.

--- middle

# Introduction

The COSE Receipts document {{-cose-receipts}} defines a common framework for expressing different types of proofs about verifiable data structures (VDS), providing a standardized way to convey trust-relevant evidence. For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the VDS, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the VDS at a later time.

In this document, we define a new type of VDS and inclusion proof associated with an application of the Confidential Consortium Framework (CCF) ledger that implements the SCITT Architecture defined in {{-scitt-architecture}}. This VDS carries indexed transaction information in a binary Merkle Tree, where new transactions are appended to the right, so that the binary decomposition of the index of a transaction can be interpreted as the position in the tree if 0 represents the left branch and 1 the right branch.
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

`data-hash` summarizes the application data included in the ledger at this transaction, which is a Signed Statement as defined by {{-scitt-architecture}}. The hash function used for `data-hash` is also the same hash function `H` as in the Merkle Tree construction for the selected verifiable data structure algorithm. For `CCF_LEDGER_SHA256`, this function is `SHA256`.

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
  &(path: 2) => [+ ccf-proof-element]
}
~~~
{: #ccf-inclusion-proof-cddl title="CCF Inclusion Proof CDDL"}

Unlike some other tree algorithms, the index of the element in the tree is not explicit in the inclusion proof, but the list of left-or-right bits can be treated as the binary decomposition of the index, from the least significant (leaf) to the most significant (root).

## CCF Inclusion Proof Signature

The proof signature for a CCF inclusion proof is a COSE signature (encoded with the `COSE_Sign1` CBOR type) which includes the following additional requirements for protected and unprotected headers. These follow the conventions of {{Section 5.2.1 of -cose-receipts}}; the corresponding CDDL is given in {{receipt-usage}}. Please note that there may be additional header parameters defined by the application.

The protected header parameters for the CCF inclusion proof signature MUST include the following:

* `vds` (label 395): `int`. This header MUST be set to the verifiable data structure algorithm identifier for `CCF_LEDGER_SHA256` (`TBD_1`).

The unprotected header for a CCF inclusion proof signature MUST include the following:

* `vdp` (label 396): map. This header conveys the verifiable data structure proofs, keyed by proof type. It MUST contain the `inclusion-proof` (-1) key, whose value is an array of one or more `ccf-inclusion-proof` values as defined above. The proof type is identified solely by this key; no other header parameter is used to convey it.

The payload of the signature is the CCF ledger Merkle root digest, and MUST be detached in order to force verifiers to recompute the root from the inclusion proofs in the unprotected header. This provides a safeguard against implementation errors that use the payload of the signature but do not recompute the root from the inclusion proof. When the array contains more than one inclusion proof, every proof MUST compute to the same root.

## Inclusion Proof Verification Algorithm

CCF uses the following algorithm to verify an inclusion receipt:

~~~
compute_root(proof):
  h := HASH(
       proof.leaf.internal-transaction-hash
           || HASH(proof.leaf.internal-evidence)
           || proof.leaf.data-hash
       )

  for [left, hash] in proof.path:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_inclusion_receipt(inclusion_receipt):
  assert(VDP_LABEL in inclusion_receipt.unprotected_header)
  let vdp = inclusion_receipt.unprotected_header[VDP_LABEL]
  assert(INCLUSION_PROOF_LABEL in vdp)
  let proofs = vdp[INCLUSION_PROOF_LABEL]
  assert(len(proofs) > 0)
  assert(inclusion_receipt.payload == nil)

  for proof in proofs:
      # Use the Merkle Root as the detached payload
      let payload = compute_root(proof)
      assert(verify_cose(inclusion_receipt, payload))
  return true
~~~
{: #ccf-inclusion-receipt-verification title="CCF Inclusion Receipt Verification"}

`VDP_LABEL` is the `vdp` header parameter label (396) and `INCLUSION_PROOF_LABEL` is the `inclusion-proof` proof type label (-1), both defined by {{-cose-receipts}}. Each element of `proofs` is a `ccf-inclusion-proof`, i.e., a byte string wrapping a CBOR-encoded map, which is decoded before `compute_root` is applied.

A description can also be found at {{CCF-Receipt-Verification}}.

# Usage in COSE Receipts {#receipt-usage}

A COSE Receipt with a CCF inclusion proof is described by the following CDDL definition, which follows {{Section 5.2.1 of -cose-receipts}}:

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

The unprotected header for an inclusion proof signature is described by the following CDDL definition:

~~~ cddl
inclusion-proof = ccf-inclusion-proof

inclusion-proofs = [ + inclusion-proof ]

verifiable-proofs = {
  &(inclusion-proof: -1) => inclusion-proofs
}

unprotected-header-map = {
  &(vdp: 396) => verifiable-proofs
  * cose-label => cose-value
}
~~~
{: #unprotected-header-map-cddl title="Unprotected Header Map CDDL"}

- vdp (label: 396): REQUIRED. Verifiable data structure proofs. Value type: map.
- inclusion-proof (label: -1): REQUIRED. Inclusion proofs. Value type: array of `ccf-inclusion-proof`.

The proof type is conveyed by the key of the `vdp` map, as specified by {{-cose-receipts}}; it is not carried in a separate header parameter.

# Privacy Considerations

See the privacy considerations section of:

*  {{-cose-receipts}}

# Security Considerations

The security considerations of {{-cose-receipts}} apply.

## Trusted Execution Environments

CCF networks of nodes rely on executing in TEEs to secure their function, in particular:

1. The evaluation of registration policies
2. The creation and usage of receipt signing keys

A compromise in the TEE platform used to execute the network may allow an attacker to produce invalid and divergent ledger branches.
Clients can mitigate this risk in two ways: by regularly auditing the consistency of the CCF ledger; and by regularly fetching attestation information about the TEE instances, available in the ledger and from the network itself, and confirming that the nodes composing the network are running up-to-date, trusted platform components.

## Operators

An operator has the ability to start successor networks with a distinct identity. The operator of a CCF network can recover the service by starting a successor network, for example a new CCF network with its own service identity, that endorses the ledger state of the previous instance. This provides service continuity after a catastrophic failure of a majority of the nodes. However, a malicious operator could exploit this mechanism and truncate the ledger’s history by initializing the successor network from an earlier ledger prefix, thereby omitting some later entries. Clients can mitigate this risk by auditing the successor ledger and verifying that their latest known receipts from the prior service are included in the successor’s ledger.

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

This document requests IANA to add the following new entry to the "COSE Verifiable Data Structure Proofs" registry:

* Verifiable Data Structure: TBD_1 (requested assignment 2)
* Name: inclusion proofs
* Label: -1
* CBOR Type: array (of bstr)
* Description: Proof of inclusion
* Reference: {{&SELF}}, {{ccf-inclusion-proofs}} and {{receipt-usage}}
* Change Controller: IETF

--- back
