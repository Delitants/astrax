#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants
set -eu

ASTRAX_PAYLOAD_SHA256='@PAYLOAD_SHA@'
ASTRAX_EXPECTED_MEMBERS='@MEMBERS@'
ASTRAX_EXPECTED_TYPES='@TYPES@'
ASTRAX_EXPECTED_HASHES='@HASHES@'

payload_offset() {
    awk '/^__ASTRAX_PAYLOAD_BELOW__$/ { print NR + 1; found = 1; exit } END { if (!found) exit 1 }' "$0"
}

verify_payload() {
    actual=$(sha256sum "$1" | cut -d ' ' -f 1)
    [ "$actual" = "$ASTRAX_PAYLOAD_SHA256" ] || { echo 'payload SHA-256 mismatch' >&2; return 1; }
    actual_members=$(tar -tzf "$1") || { echo 'invalid payload archive' >&2; return 1; }
    [ "$actual_members" = "$ASTRAX_EXPECTED_MEMBERS" ] || { echo 'payload member list mismatch' >&2; return 1; }
    verbose=$(tar -tvzf "$1") || return 1
    actual_types=$(printf '%s\n' "$verbose" | awk '{ print substr($1, 1, 1) }')
    [ "$actual_types" = "$ASTRAX_EXPECTED_TYPES" ] || { echo 'payload member type mismatch' >&2; return 1; }
    printf '%s\n' "$verbose" | grep -E '^l.*[[:space:]]lib/libastrax_srt\.so\.1 -> libastrax_srt\.so\.1\.4\.0$' >/dev/null || {
        echo 'invalid SRT SONAME symlink' >&2
        return 1
    }
    for entry in $ASTRAX_EXPECTED_HASHES; do
        name=${entry%%:*}
        expected=${entry#*:}
        tar -xOzf "$1" "$name" > "$work/check" || return 1
        actual=$(sha256sum "$work/check" | cut -d ' ' -f 1)
        [ "$actual" = "$expected" ] || { echo "payload file sha256 mismatch: $name" >&2; return 1; }
    done
}

extract_payload() {
    archive=$1
    destination=$2
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || { echo 'destination exists' >&2; return 1; }
    mkdir -m 700 "$destination" || return 1
    for name in $ASTRAX_EXPECTED_MEMBERS; do
        mkdir -p "$destination/$(dirname "$name")"
        if [ "$name" = 'lib/libastrax_srt.so.1' ]; then
            ln -s libastrax_srt.so.1.4.0 "$destination/$name"
        else
            tar -xOzf "$archive" "$name" > "$destination/$name" || return 1
            if [ "$name" = astrax ]; then chmod 755 "$destination/$name"; else chmod 644 "$destination/$name"; fi
        fi
    done
}

usage() {
    echo 'QA-only AstraX package (not for distribution or installation)'
    echo 'Usage: astrax-QA-ONLY.run --help | --verify | --extract DIR'
}

case ${1-} in
    --help) [ "$#" -eq 1 ] || exit 2; usage; exit 0 ;;
    --verify) [ "$#" -eq 1 ] || exit 2; mode=$1 ;;
    --extract) [ "$#" -eq 2 ] || exit 2; mode=$1; destination=$2 ;;
    --install|--activate) echo 'QA-only package cannot install or activate' >&2; exit 2 ;;
    *) usage >&2; exit 2 ;;
esac

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/astrax-qa-run.XXXXXX") || exit 1
trap 'rm -rf "$work"' 0
trap 'exit 1' 1 2 3 15
offset=$(payload_offset) || { echo 'payload marker missing' >&2; exit 1; }
tail -n "+$offset" "$0" > "$work/payload.tar.gz"
verify_payload "$work/payload.tar.gz" || exit 1

case $mode in
    --verify) echo 'QA-only AstraX payload verified' ;;
    --extract) extract_payload "$work/payload.tar.gz" "$destination" ;;
esac

exit 0
__ASTRAX_PAYLOAD_BELOW__
