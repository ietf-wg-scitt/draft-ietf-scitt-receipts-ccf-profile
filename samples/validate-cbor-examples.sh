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
  chk/cddl/ccf-receipt-cddl.cddl \
  chk/cddl/ccf-leaf-cddl.cddl \
  chk/cddl/ccf-inclusion-proof-cddl.cddl \
  chk/cddl/protected-header-map-cddl.cddl \
  chk/cddl/unprotected-header-map-cddl.cddl \
  >chk/ccf-receipt.cddl

cddlc -tcddl -2r chk/ccf-receipt.cddl -SCCF_Receipt >chk/all.cddl

echo "Validating $sample_path against extracted CDDL"
cddl chk/all.cddl validate "$sample_path"
