#!/usr/bin/env bash

set -euo pipefail

default_sample='cose-hash-envelope-0-with-microsoft-mst-receipt.scitt'

usage() {
    echo "usage: $0 XML_PATH [SAMPLE_PATH]" >&2
    exit 1
}

xml_path=''
sample_path=''

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            ;;
        -*)
            usage
            ;;
        *)
            if [ -z "$xml_path" ]; then
                xml_path="$1"
            elif [ -z "$sample_path" ]; then
                sample_path="$1"
            else
                usage
            fi
            shift
            ;;
    esac
done

[ -n "$xml_path" ] || usage

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
xml_path="$(realpath "$xml_path")"
sample_path="${sample_path:-$script_dir/$default_sample}"
sample_path="$(realpath "$sample_path")"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

cd "$workdir"
kramdown-rfc-extract-sourcecode -dchk "$xml_path"

cat >chk/ccf-receipt.cddl <<'EOF'
CCF_Receipt = #6.18(Signed_CCF_Inclusion_Proof)

Signed_CCF_Inclusion_Proof = [
  protected: bstr .cbor protected-header-map,
  unprotected: unprotected-header-map,
  payload: nil,
  signature: bstr,
]

cose-label = int / tstr
cose-value = any

EOF

cat \
  chk/cddl/ccf-leaf-cddl.cddl \
  chk/cddl/ccf-inclusion-proof-cddl.cddl \
  chk/cddl/protected-header-map-cddl.cddl \
  chk/cddl/unprotected-header-map-cddl.cddl \
  >>chk/ccf-receipt.cddl

cddlc -tcddl -2rTverifiable-proofs chk/ccf-receipt.cddl -SCCF_Receipt >chk/all.cddl

python3 - "$sample_path" "$workdir" <<'PY'
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import cbor2

sample_path = Path(sys.argv[1])
workdir = Path(sys.argv[2])
value = cbor2.loads(sample_path.read_bytes())

if not isinstance(value, cbor2.CBORTag) or value.tag != 18:
    raise SystemExit(f"{sample_path} is not a COSE_Sign1 message")

if not isinstance(value.value, Sequence) or isinstance(value.value, (bytes, bytearray, str)) or len(value.value) != 4:
    raise SystemExit(f"{sample_path} is not a COSE_Sign1 array")

unprotected = value.value[1]
if not isinstance(unprotected, Mapping):
    raise SystemExit(f"{sample_path} has no COSE_Sign1 unprotected header map")

if 396 in unprotected:
    receipts = [cbor2.dumps(value)]
elif 394 in unprotected:
    receipts = unprotected[394]
else:
    raise SystemExit(f"{sample_path} does not contain a COSE receipt")

for index, receipt in enumerate(receipts, start=1):
    if isinstance(receipt, bytes):
        receipt_bytes = receipt
    else:
        receipt_bytes = cbor2.dumps(receipt)

    path = workdir / f"receipt-{index}.cbor"
    path.write_bytes(receipt_bytes)
    print(path)
PY

for receipt_path in receipt-*.cbor; do
    echo "Validating $receipt_path against extracted CDDL"
    cddl chk/all.cddl validate "$receipt_path"
done
