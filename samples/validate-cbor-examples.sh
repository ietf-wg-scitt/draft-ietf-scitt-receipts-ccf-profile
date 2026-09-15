#!/usr/bin/env bash

set -euo pipefail

default_sample='microsoft-mst-receipt.cbor'

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

cat \
  "$script_dir/cose-receipt.cddl" \
  chk/cddl/ccf-leaf-cddl.cddl \
  chk/cddl/ccf-inclusion-proof-cddl.cddl \
  chk/cddl/ccf-consistency-proof-cddl.cddl \
  chk/cddl/protected-header-map-cddl.cddl \
  chk/cddl/unprotected-header-map-cddl.cddl \
  >chk/ccf-receipt.cddl

cddlc -tcddl -2r chk/ccf-receipt.cddl -SCCF_Receipt >chk/all.cddl

echo "Validating $sample_path against extracted CDDL"
cddl chk/all.cddl validate "$sample_path"

cddlc -tcddl -2r chk/ccf-receipt.cddl -Sccf-consistency-proof >chk/consistency-proof.cddl
consistency_dir="$script_dir/consistency-proofs"

for f in "$consistency_dir"/valid/*.cbor; do
    echo "Validating ${f#"$script_dir"/} against ccf-consistency-proof"
    cddl chk/consistency-proof.cddl validate "$f"
done

for f in "$consistency_dir"/invalid/cddl-*.cbor; do
    echo "Expecting ${f#"$script_dir"/} to be rejected by ccf-consistency-proof"
    if cddl chk/consistency-proof.cddl validate "$f" 2>/dev/null; then
        echo "error: $f unexpectedly validates" >&2
        exit 1
    fi
done

python3 "$consistency_dir/verify.py" "$consistency_dir"
