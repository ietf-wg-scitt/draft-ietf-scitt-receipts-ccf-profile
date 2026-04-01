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
  I-D.ietf-wg-scitt-architecture: scitt-architecture

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

--- abstract

This document defines a new verifiable data structure type for COSE Signed Merkle Tree Proofs specifically designed for transaction ledgers produced via Trusted Execution Environments (TEEs), such as the Confidential Consortium Framework ({{CCF}}) to provide stronger tamper-evidence guarantees.

--- middle

# Introduction

The COSE Receipts document {{-cose-receipts}} defines a common framework for defining different types of proofs, such as proof of inclusion, about verifiable data structures (VDS). For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the VDS, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the VDS at a later time.

In this document, we define a new type of VDS, associated with an application of the Confidential Consortium Framework (CCF) ledger that implements the SCITT Architecture defined in {{-scitt-architecture}}. This VDS carries indexed transaction information in a binary Merkle Tree, where new transactions are appended to the right, so that the binary decomposition of the index of a transaction can be interpreted as the position in the tree if 0 represents the left branch and 1 the right branch.
Compared to {{RFC9162}}, the leaves of CCF trees carry additional internal information for the following purposes:

1. To bind the full details of the transaction executed, which is a super-set of what is exposed in the proof and captures internal information details useful for detailed system audit, but not for application purposes.
1. To allow the distributed system executing the application logic in Trusted Excecution Environments to persist signatures to storage early, but only enable receipt production once they are fully committed by the consensus protocol.

## Requirements Notation

{::boilerplate bcp14-tagged}

# Description of the CCF Ledger Verifiable Data Structure

This documents extends the verifiable data structure registry of {{-cose-receipts}} with the following value:

| Name | Value | Description | Reference
|---
|CCF_LEDGER_SHA256 | TBD_1 (requested assignment 2) | Historical transaction ledgers, such as the CCF ledger | RFCthis
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

This document defines inclusion proofs for CCF ledgers.

## Merkle Tree Shape

A CCF ledger is a binary Merkle Tree constructed from a hash function H, which is defined from the log type. For instance, the hash function for `CCF_LEDGER_SHA256` is `SHA256`, whose `HASH_SIZE` is 32 bytes.

The Merkle tree encodes an ordered list of `n` transactions T_n = \{T\[0\], T\[1\], ..., T\[n-1\]\}. We define the Merkle Tree Hash (MTH) function, which takes as input a list of serialized transactions (as byte strings), and outputs a single HASH_SIZE byte string called the Merkle root hash, by induction on the list.

This function is defined as follows:

The hash of an empty list is the hash of an empty string:

~~~
MTH({}) = HASH().
~~~

The hash of a list with one entry (also known as a leaf hash) is:

~~~
MTH({d[0]}) = HASH(d[0]).
~~~

For n > 1, let k be the largest power of two smaller than n (i.e., k < n <= 2k). The Merkle Tree Hash of an n-element list D_n is then defined recursively as:

~~~
MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n])),
~~~

where:

- \|\| denotes concatenation
- : denotes concatenation of lists
- D\[k1:k2\] = D'_(k2-k1) denotes the list \{d'\[0\] = d\[k1\], d'\[1\] = d\[k1+1\], ..., d'\[k2-k1-1\] = d\[k2-1\]\} of length (k2 - k1).

## Transaction Components

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

The `internal-transaction-hash` and `internal-evidence` byte strings are internal to the CCF implementation. They can be safely ignored by receipt Verifiers, but they commit the TS to the whole tree contents and may be used for additional, CCF-specific auditing.

`internal-transaction-hash` is a hash over the complete entry in the {{CCF-Ledger-Format}}, and `internal-evidence` is a revealable {{CCF-Commit-Evidence}} value that allows early persistence of ledger entries before distributed consensus can be established. This mechanism is useful to implement high-throughput transparency applications in Trusted Execution Environments that only provide a limited amount of memory, while maintaining high availability afforded by distributed consensus.

`data-hash` summarises the application data included in the ledger at this transaction, which is a Signed Statement as defined by {{-scitt-architecture}}.

# CCF Inclusion Proofs

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

Unlike some other tree algorithms, the index of the element in the tree is not explicit in the inclusion proof, but the list of left-or-right bits can be treated as the binary decomposition of the index, from the least significant (leaf) to the most significant (root).

## CCF Inclusion Proof Signature

The proof signature for a CCF inclusion proof is a COSE signature (encoded with the `COSE_Sign1` CBOR type) which includes the following additional requirements for protected and unprotected headers. Please note that there may be additional header parameters defined by the application.

The protected header parameters for the CCF inclusion proof signature MUST include the following:

* `verifiable-data-structure: int/tstr`. This header MUST be set to the verifiable data structure algorithm identifier for `ccf-ledger` (TBD_1).
* `label: int`. This header MUST be set to the value of the `inclusion` proof type in the IANA registry of Verifiable Data Structure Proof Type (-1).

The unprotected header for a CCF inclusion proof signature MUST include the following:

* `inclusion-proof: bstr .cbor ccf-inclusion-proof`. This contains the serialized CCF inclusion proof, as defined above.

The payload of the signature is the CCF ledger Merkle root digest, and MUST be detached in order to force verifiers to recompute the root from the inclusion proof in the unprotected header. This provides a safeguard against implementation errors that use the payload of the signature but do not recompute the root from the inclusion proof.

## Inclusion Proof Verification Algorithm

CCF uses the following algorithm to verify an inclusion receipt:

~~~
compute_root(proof):
  h := proof.leaf.internal-transaction-hash
       || HASH(proof.leaf.internal-evidence)
       || proof.leaf.data-hash

  for [left, hash] in proof:
      h := HASH(hash + h) if left
           HASH(h + hash) else
  return h

verify_inclusion_receipt(inclusion_receipt):
  let label = INCLUSION_PROOF_LABEL
  assert(label in inclusion_receipt.unprotected_header)
  let proof = inclusion_receipt.unprotected_header[label]
  assert(inclusion_receipt.payload == nil)
  let payload = compute_root(proof)

  # Use the Merkle Root as the detached payload
  return verify_cose(inclusion_receipt, payload)
~~~

A description can also be found at {{CCF-Receipt-Verification}}.

# Usage in COSE Receipts

A COSE Receipt with a CCF inclusion proof is described by the following CDDL definition:

~~~ cddl
protected-header-map = {
  &(alg: 1) => int
  &(vds: 395) => 2
  * cose-label => cose-value
}
~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier. Value type: int.

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

# Privacy Considerations

See the privacy considerations section of:

*  {{-cose-receipts}}

# Security Considerations

The security consideration of {{-cose-receipts}} apply.

## Trusted Execution Environments

CCF networks of nodes rely on executing in Trusted Execution Environments to secure their function, in particular:

1. The evaluation of registration policies
2. The creation and usage of receipt signing keys

A compromise in the Trusted Execution Environment platform used to execute the network may allow an attacker to produce invalid and incompatible ledger branches.
Clients can mitigate this risk in two ways: by regularly auditing the consistency of the CCF ledger; and by regularly fetching attestation information about the TEE instances, available in the ledger and from the network itself, and confirming that the nodes composing the network are running up-to-date, trusted platform components.

## Operators

The operator of a CCF network has the ability to start successor networks, with a distinct identity, which endorse the receipts produced by a previous instance.
This functionality is important to provide service continuity in the case of a catastrophic failure of a majority of nodes, but allows a potentially malicious operator to start from a prefix of an earlier ledger.
Clients can mitigate this risk by auditing the successor ledger and its attestation information, as described above. In particular, clients can check that the latest receipt they hold is present in the successor ledger before they begin making use of it.

# IANA Considerations

## Additions to Existing Registries

### Tree Algorithms {#tree-alg-registry}

This document requests IANA to add the following new value to the 'COSE Verifiable Data Structures' registry:

* Name: CCF_LEDGER_SHA256
* Value: 2 (requested assignment)
* Description: Append-only logs that are integrity-protected by a Merkle Tree and signatures produced via Trusted Execution Environments containing a mix of public and confidential information, as specified by the Confidential Consortium Framework.
* Reference: This document

--- back
