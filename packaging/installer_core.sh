#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

astrax_detect_init() {
    root=$1
    comm=$(cat "$root/proc/1/comm" 2>/dev/null) || return 1
    if [ "$comm" = systemd ] && [ -d "$root/run/systemd/system" ]; then
        echo systemd
    elif [ -f "$root/run/openrc/softlevel" ] && [ -d "$root/etc/init.d" ]; then
        echo openrc
    elif [ "$comm" = init ] && [ -d "$root/etc/init.d" ]; then
        echo sysv
    else
        echo 'unsupported init system' >&2
        return 1
    fi
}

astrax_account_entry_compatible() {
    passwd=$1
    group=$2
    name=$(printf '%s\n' "$passwd" | cut -d: -f1)
    uid=$(printf '%s\n' "$passwd" | cut -d: -f3)
    gid=$(printf '%s\n' "$passwd" | cut -d: -f4)
    home=$(printf '%s\n' "$passwd" | cut -d: -f6)
    shell=$(printf '%s\n' "$passwd" | cut -d: -f7)
    group_name=$(printf '%s\n' "$group" | cut -d: -f1)
    group_gid=$(printf '%s\n' "$group" | cut -d: -f3)
    case "$uid:$gid:$group_gid" in *[!0-9:]*|:*) return 1 ;; esac
    [ "$name" = astrax ] && [ "$group_name" = astrax ] &&
        [ "$uid" -lt 1000 ] && [ "$gid" = "$group_gid" ] &&
        [ "$home" = /var/lib/astrax ] || return 1
    case "$shell" in */nologin) return 0 ;; *) return 1 ;; esac
}

astrax_account_status() {
    root=$1
    if [ "$root" != / ]; then
        [ ! -e "$root/qa/account-incompatible" ] || { echo incompatible; return; }
        if [ -f "$root/qa/account" ]; then echo compatible; else echo absent; fi
        return
    fi
    entry=$(getent passwd astrax 2>/dev/null) || { echo absent; return; }
    group=$(getent group astrax 2>/dev/null) || { echo incompatible; return; }
    if astrax_account_entry_compatible "$entry" "$group"; then
        echo compatible
    else
        echo incompatible
    fi
}

astrax_ldconfig_path() {
    printf '%s\n' "$1" | awk -v lib="$2" '$1 == lib && $2 == "(libc6,x86-64)" && $3 == "=>" { print $4; exit }'
}

astrax_check_abi() {
    root=$1
    if [ "$root" != / ]; then
        [ -f "$root/qa/abi-ok" ] || { echo 'ABI fixture missing' >&2; return 1; }
        return 0
    fi
    [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'Linux x86-64 required' >&2; return 1; }
    [ -e /lib64/ld-linux-x86-64.so.2 ] || { echo 'glibc ELF loader missing' >&2; return 1; }
    for tool in getconf ldconfig strings; do
        command -v "$tool" >/dev/null 2>&1 || { echo "required compatibility tool missing: $tool" >&2; return 1; }
    done
    version=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
    major=${version%%.*}
    minor=${version#*.}
    case "$major:$minor" in *[!0-9:]*|:*) echo 'glibc version unavailable' >&2; return 1 ;; esac
    if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 38 ]; }; then
        echo 'glibc 2.38 or newer required' >&2
        return 1
    fi
    libs=$(ldconfig -p 2>/dev/null) || return 1
    for lib in libcrypto.so.3 libstdc++.so.6 libgcc_s.so.1 libm.so.6 libc.so.6; do
        path=$(astrax_ldconfig_path "$libs" "$lib")
        [ -n "$path" ] && [ -f "$path" ] || { echo "missing x86-64 $lib" >&2; return 1; }
        if [ "$lib" = libstdc++.so.6 ]; then cxx=$path; fi
    done
    strings "$cxx" | grep -qx GLIBCXX_3.4.32 || {
        echo 'libstdc++ with GLIBCXX_3.4.32 required' >&2
        return 1
    }
}

astrax_service_path() {
    root=$1
    init=$2
    if [ "$init" = systemd ]; then
        echo "$root/etc/systemd/system/astrax.service"
    else
        echo "$root/etc/init.d/astrax"
    fi
}

astrax_preflight() {
    root=$1
    payload=$2
    [ "$root" != / ] || [ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; return 1; }
    [ -f "$payload/astrax" ] && [ -f "$payload/MANIFEST.json" ] && [ -f "$payload/lib/libastrax_srt.so.1.4.0" ] || {
        echo 'incomplete verified payload' >&2; return 1
    }
    astrax_check_abi "$root" || return 1
    init=$(astrax_detect_init "$root") || return 1
    service=$(astrax_service_path "$root" "$init")
    for path in "$root/opt/astrax" "$root/var/lib/astrax" \
        "$root/etc/systemd/system/astrax.service" "$root/etc/init.d/astrax"; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "existing path: $path" >&2; return 1; }
    done
    [ "$(astrax_account_status "$root")" != incompatible ] || { echo 'incompatible astrax account' >&2; return 1; }
    if [ "$root" = / ]; then
        case "$init" in
            systemd) command -v systemctl >/dev/null 2>&1 || return 1 ;;
            openrc) command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 || return 1 ;;
            sysv) command -v start-stop-daemon >/dev/null 2>&1 && command -v update-rc.d >/dev/null 2>&1 || return 1 ;;
        esac
        command -v useradd >/dev/null 2>&1 || return 1
    fi
    echo "$init"
}

astrax_rollback() {
    [ -z "${astrax_stage:-}" ] || rm -rf "$astrax_stage"
    [ -z "${astrax_service_stage:-}" ] || rm -f "$astrax_service_stage"
    [ "${astrax_created_service:-0}" -eq 0 ] || rm -f "$astrax_service"
    [ "${astrax_created_runtime:-0}" -eq 0 ] || rm -rf "$astrax_root/opt/astrax"
    [ "${astrax_created_state:-0}" -eq 0 ] || rm -rf "$astrax_root/var/lib/astrax"
    if [ "${astrax_created_account:-0}" -eq 1 ]; then
        if [ "$astrax_root" = / ]; then userdel astrax; else rm -f "$astrax_root/qa/account"; fi
    fi
}

astrax_install() {
    astrax_root=$1
    payload=$2
    astrax_init=$(astrax_preflight "$astrax_root" "$payload") || return 1
    astrax_service=$(astrax_service_path "$astrax_root" "$astrax_init")
    astrax_created_account=0
    astrax_created_state=0
    astrax_created_runtime=0
    astrax_created_service=0
    astrax_service_stage=
    mkdir -p "$astrax_root/opt" || return 1
    astrax_stage=$(mktemp -d "$astrax_root/opt/.astrax-stage.XXXXXX") || return 1
    trap 'astrax_rollback' 0
    trap 'exit 1' 1 2 3 15
    cp -R "$payload/." "$astrax_stage/" || return 1
    if [ "$(astrax_account_status "$astrax_root")" = absent ]; then
        if [ "$astrax_root" = / ]; then
            useradd --system --user-group --home-dir /var/lib/astrax --shell /usr/sbin/nologin astrax || return 1
        else
            printf 'compatible' > "$astrax_root/qa/account" || return 1
        fi
        astrax_created_account=1
    fi
    if [ "$astrax_root" = / ]; then
        if getent group video >/dev/null 2>&1 && [ "$astrax_created_account" -eq 1 ]; then
            usermod -aG video astrax || return 1
        elif getent group video >/dev/null 2>&1; then
            if ! id -nG astrax | tr ' ' '\n' | grep -qx video; then
                echo 'existing astrax account lacks video group; configure DVB access separately' >&2
            fi
        else
            echo 'video group absent; configure DVB device access separately' >&2
        fi
    elif [ ! -f "$astrax_root/qa/video-group" ]; then
        echo 'video group absent; configure DVB device access separately' >&2
    fi
    mkdir -p "$astrax_root/var/lib/astrax" || return 1
    astrax_created_state=1
    chmod 700 "$astrax_root/var/lib/astrax" || return 1
    if [ "$astrax_root" = / ]; then chown astrax:astrax "$astrax_root/var/lib/astrax" || return 1; fi
    if [ "$astrax_root" != / ] && [ "${ASTRAX_TEST_RACE_CREATE_RUNTIME:-}" = 1 ]; then
        mkdir "$astrax_root/opt/astrax" || return 1
        printf 'keep me' > "$astrax_root/opt/astrax/preexisting"
    fi
    mkdir "$astrax_root/opt/astrax" || return 1
    astrax_created_runtime=1
    cp -R "$astrax_stage/." "$astrax_root/opt/astrax/" || return 1
    find "$astrax_root/opt/astrax" -type d -exec chmod 755 {} \; || return 1
    find "$astrax_root/opt/astrax" -type f -exec chmod 644 {} + || return 1
    chmod 755 "$astrax_root/opt/astrax/astrax" || return 1
    rm -rf "$astrax_stage"
    astrax_stage=
    if [ "$astrax_root" != / ] && [ "${ASTRAX_TEST_FAIL_AFTER:-}" = runtime ]; then
        echo 'injected runtime failure' >&2
        return 1
    fi
    template_dir=${ASTRAX_TEMPLATE_DIR:-}
    [ -n "$template_dir" ] && [ -f "$template_dir/$astrax_init.in" ] || { echo 'init template missing' >&2; return 1; }
    mkdir -p "$(dirname "$astrax_service")" || return 1
    astrax_service_stage=$(mktemp "$(dirname "$astrax_service")/.astrax-service.XXXXXX") || return 1
    cp "$template_dir/$astrax_init.in" "$astrax_service_stage" || return 1
    if [ "$astrax_root" != / ] && [ "${ASTRAX_TEST_FAIL_SERVICE_STAGE:-}" = 1 ]; then
        echo 'injected service staging failure' >&2
        return 1
    fi
    if [ "$astrax_init" = systemd ]; then chmod 644 "$astrax_service_stage"; else chmod 755 "$astrax_service_stage"; fi
    ln "$astrax_service_stage" "$astrax_service" || return 1
    astrax_created_service=1
    rm -f "$astrax_service_stage"
    astrax_service_stage=
    if [ "$astrax_root" = / ] && [ "$astrax_init" = systemd ]; then systemctl daemon-reload || return 1; fi
    trap - 0 1 2 3 15
    echo "AstraX installed; $astrax_init service created but not enabled or started"
}

astrax_service_enabled() {
    root=$1
    init=$2
    if [ "$root" != / ]; then [ -f "$root/qa/service-enabled" ]; return; fi
    case "$init" in
        systemd) systemctl is-enabled --quiet astrax.service ;;
        openrc) rc-update show default | grep -Eq '(^|[[:space:]])astrax([[:space:]]|$)' ;;
        sysv) ls /etc/rc[2-5].d/S*astrax >/dev/null 2>&1 ;;
    esac
}

astrax_enable_service() {
    root=$1
    init=$2
    if [ "$root" != / ]; then
        [ "${ASTRAX_TEST_FAIL_ENABLE:-}" != 1 ] || return 1
        printf 'enable\n' >> "$root/qa/service-actions"
        : > "$root/qa/service-enabled"
        return 0
    fi
    case "$init" in
        systemd) systemctl enable astrax.service ;;
        openrc) rc-update add astrax default ;;
        sysv) update-rc.d astrax defaults ;;
    esac
}

astrax_start_service() {
    root=$1
    init=$2
    if [ "$root" != / ]; then
        printf 'start\n' >> "$root/qa/service-actions"
        [ "${ASTRAX_TEST_FAIL_START:-}" != 1 ]
        return $?
    fi
    case "$init" in
        systemd) systemctl start astrax.service ;;
        openrc) rc-service astrax start ;;
        sysv) /etc/init.d/astrax start ;;
    esac
}

astrax_disable_service() {
    root=$1
    init=$2
    if [ "$root" != / ]; then
        printf 'disable\n' >> "$root/qa/service-actions"
        rm -f "$root/qa/service-enabled"
        return 0
    fi
    case "$init" in
        systemd) systemctl disable astrax.service ;;
        openrc) rc-update del astrax default ;;
        sysv) update-rc.d astrax remove ;;
    esac
}

astrax_activate() {
    root=$1
    payload=$2
    [ "$root" != / ] || [ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; return 1; }
    astrax_check_abi "$root" || return 1
    init=$(astrax_detect_init "$root") || return 1
    service=$(astrax_service_path "$root" "$init")
    template_dir=${ASTRAX_TEMPLATE_DIR:-}
    [ -f "$template_dir/$init.in" ] && [ -f "$service" ] || { echo 'service definition missing' >&2; return 1; }
    for name in astrax MANIFEST.json lib/libastrax_srt.so.1.4.0; do
        cmp -s "$root/opt/astrax/$name" "$payload/$name" || {
            echo "installed $name does not match this package" >&2
            return 1
        }
    done
    [ "$(readlink "$root/opt/astrax/lib/libastrax_srt.so.1" 2>/dev/null)" = libastrax_srt.so.1.4.0 ] || {
        echo 'installed SRT SONAME link mismatch' >&2; return 1
    }
    cmp -s "$service" "$template_dir/$init.in" || { echo 'service definition mismatch' >&2; return 1; }
    [ -d "$root/var/lib/astrax" ] || { echo 'state directory missing' >&2; return 1; }
    echo "Activating AstraX via $init: $service"
    newly_enabled=0
    if ! astrax_service_enabled "$root" "$init"; then
        if ! astrax_enable_service "$root" "$init"; then
            if astrax_service_enabled "$root" "$init"; then astrax_disable_service "$root" "$init"; fi
            echo 'could not enable AstraX service' >&2
            return 1
        fi
        newly_enabled=1
    fi
    if ! astrax_start_service "$root" "$init"; then
        if [ "$newly_enabled" -eq 1 ]; then astrax_disable_service "$root" "$init"; fi
        echo 'AstraX service failed to start' >&2
        return 1
    fi
    echo 'AstraX service enabled and started'
}

if [ "${ASTRAX_CORE_LIBRARY_ONLY:-}" = 1 ]; then
    return 0
fi

case ${1-} in
    --install) [ "$#" -eq 2 ] || exit 2; astrax_install / "$2" ;;
    --activate) [ "$#" -eq 2 ] || exit 2; astrax_activate / "$2" ;;
    *) echo 'invalid installer core command' >&2; exit 2 ;;
esac
