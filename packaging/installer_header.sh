#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants
set -eu

ASTRAX_PAYLOAD_SHA256='@PAYLOAD_SHA@'
ASTRAX_PRIVATE_INSTALL_QA='@PRIVATE_INSTALL_QA@'
ASTRAX_RELEASE_TARGET='@RELEASE_TARGET@'
ASTRAX_EXPECTED_MEMBERS='@MEMBERS@'
ASTRAX_EXPECTED_TYPES='@TYPES@'
ASTRAX_EXPECTED_HASHES='@HASHES@'
ASTRAX_CORE='@CORE@'
ASTRAX_SYSTEMD_TEMPLATE='@SYSTEMD@'
ASTRAX_OPENRC_TEMPLATE='@OPENRC@'
ASTRAX_SYSV_TEMPLATE='@SYSV@'

payload_offset() {
    awk '/^__ASTRAX_PAYLOAD_BELOW__$/ { print NR + 1; found = 1; exit } END { if (!found) exit 1 }' "$0"
}

verify_payload() {
    actual=$(sha256sum "$1" | cut -d ' ' -f 1)
    [ "$actual" = "$ASTRAX_PAYLOAD_SHA256" ] || { echo 'payload SHA-256 mismatch' >&2; return 1; }
    actual_members=$(tar -tzf "$1") || { echo 'invalid payload archive' >&2; return 1; }
    [ "$actual_members" = "$ASTRAX_EXPECTED_MEMBERS" ] || { echo 'payload member list mismatch' >&2; return 1; }
    actual_types=$(tar -tvzf "$1" | awk '{ print substr($1, 1, 1) }') || return 1
    [ "$actual_types" = "$ASTRAX_EXPECTED_TYPES" ] || { echo 'payload member type mismatch' >&2; return 1; }
    tar -tvzf "$1" | grep -Eq '^l.*[[:space:]]lib/libastrax_srt\.so\.1 -> libastrax_srt\.so\.1\.4\.0$' || {
        echo 'invalid SRT SONAME symlink' >&2
        return 1
    }
    for entry in $ASTRAX_EXPECTED_HASHES; do
        name=${entry%%:*}
        expected=${entry#*:}
        actual=$(tar -xOzf "$1" "$name" | sha256sum | cut -d ' ' -f 1)
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
    echo 'Usage: astrax.run --help | --verify | --extract DIR | --install | --activate'
    [ "$ASTRAX_PRIVATE_INSTALL_QA" != 1 ] || echo 'PRIVATE INSTALLER QA - NOT FOR DISTRIBUTION; activation disabled'
}

case ${1-} in
    --help) [ "$#" -eq 1 ] || exit 2; usage; exit 0 ;;
    --verify|--install|--activate) [ "$#" -eq 1 ] || exit 2; mode=$1 ;;
    --extract) [ "$#" -eq 2 ] || exit 2; mode=$1; destination=$2 ;;
    *) usage >&2; exit 2 ;;
esac

if [ "$ASTRAX_PRIVATE_INSTALL_QA" = 1 ]; then
    if [ "$mode" = --activate ]; then
        echo 'private installer QA package cannot activate a service' >&2
        exit 1
    fi
    if [ "$mode" = --install ] && [ "${ASTRAX_PRIVATE_INSTALL_QA_ACK:-}" != 1 ]; then
        echo 'private installer QA acknowledgement required: ASTRAX_PRIVATE_INSTALL_QA_ACK=1' >&2
        exit 1
    fi
fi

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/astrax-run.XXXXXX") || exit 1
trap 'rm -rf "$work"' 0
trap 'exit 1' 1 2 3 15
offset=$(payload_offset) || { echo 'payload marker missing' >&2; exit 1; }
tail -n "+$offset" "$0" > "$work/payload.tar.gz"
verify_payload "$work/payload.tar.gz" || exit 1

case $mode in
    --verify) echo 'AstraX payload verified'; exit 0 ;;
    --extract) extract_payload "$work/payload.tar.gz" "$destination"; exit $? ;;
    --install|--activate)
        [ -n "$ASTRAX_CORE" ] || { echo 'installer core unavailable' >&2; exit 1; }
        extract_payload "$work/payload.tar.gz" "$work/release"
        printf '%s' "$ASTRAX_CORE" > "$work/installer_core.sh"
        mkdir -m 700 "$work/init"
        printf '%s' "$ASTRAX_SYSTEMD_TEMPLATE" > "$work/init/systemd.in"
        printf '%s' "$ASTRAX_OPENRC_TEMPLATE" > "$work/init/openrc.in"
        printf '%s' "$ASTRAX_SYSV_TEMPLATE" > "$work/init/sysv.in"
        ASTRAX_RELEASE_TARGET="$ASTRAX_RELEASE_TARGET" ASTRAX_TEMPLATE_DIR="$work/init" sh "$work/installer_core.sh" "$mode" "$work/release"
        exit $? ;;
esac

exit 1
__ASTRAX_PAYLOAD_BELOW__
