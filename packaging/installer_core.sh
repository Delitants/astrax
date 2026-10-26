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
        [ "$uid" -gt 0 ] && [ "$uid" -lt 1000 ] &&
        [ "$gid" -gt 0 ] && [ "$gid" = "$group_gid" ] &&
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

astrax_has_glibcxx_3_4_32() {
    LC_ALL=C tr '\000' '\n' < "$1" | grep -Fqx 'GLIBCXX_3.4.32'
}

astrax_check_abi() {
    root=$1
    if [ "$root" != / ]; then
        [ -f "$root/qa/abi-ok" ] || { echo 'ABI fixture missing' >&2; return 1; }
        return 0
    fi
    [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'Linux x86-64 required' >&2; return 1; }
    [ -e /lib64/ld-linux-x86-64.so.2 ] || { echo 'glibc ELF loader missing' >&2; return 1; }
    for tool in getconf ldconfig tr; do
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
    astrax_has_glibcxx_3_4_32 "$cxx" || {
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

astrax_check_release_target() {
    root=$1
    init=$2
    case ${ASTRAX_RELEASE_TARGET:-} in
        '') return 0 ;;
        ubuntu-24.04-amd64-systemd)
            [ "$init" = systemd ] && [ -f "$root/etc/os-release" ] &&
                grep -Eq '^ID="?ubuntu"?$' "$root/etc/os-release" &&
                grep -Eq '^VERSION_ID="?24\.04"?$' "$root/etc/os-release" || {
                    echo 'Ubuntu 24.04 amd64 with systemd required for this release' >&2
                    return 1
                } ;;
        *) echo 'unsupported release target' >&2; return 1 ;;
    esac
}

astrax_check_parent_paths() {
    for astrax_parent in "$1/opt" "$1/var" "$1/var/lib" "$1/etc" "$1/etc/sudoers.d" \
        "$1/etc/systemd" "$1/etc/systemd/system" "$1/etc/init.d"; do
        [ ! -L "$astrax_parent" ] || { echo "symlink parent: $astrax_parent" >&2; return 1; }
        if [ -e "$astrax_parent" ]; then
            [ -d "$astrax_parent" ] || return 1
            if [ "$1" = / ]; then
                [ -n "$(find "$astrax_parent" -prune -uid 0 -gid 0 ! -perm -020 ! -perm -002 -print)" ] || {
                    echo "unsafe parent ownership/mode: $astrax_parent" >&2; return 1
                }
            fi
        fi
    done
}

astrax_check_dvb_tools() {
    for astrax_tool in "$1/usr/bin/sudo" "$1/usr/sbin/visudo"; do
        [ -x "$astrax_tool" ] || { echo "required DVB ownership tool missing: $astrax_tool" >&2; return 1; }
    done
}

astrax_secure_file() {
    [ -f "$2" ] && [ ! -L "$2" ] && [ -n "$(find "$2" -prune -type f -perm "$3" -print)" ] || {
        echo "unsafe file type/mode: $2" >&2; return 1
    }
    if [ "$1" = / ]; then
        [ -n "$(find "$2" -prune -uid 0 -gid 0 -print)" ] || {
            echo "file must be root:root: $2" >&2; return 1
        }
    fi
}

astrax_secure_directory() {
    [ -d "$2" ] && [ ! -L "$2" ] && [ -n "$(find "$2" -prune -type d -perm 755 -print)" ] || {
        echo "unsafe runtime directory: $2" >&2; return 1
    }
    if [ "$1" = / ]; then
        [ -n "$(find "$2" -prune -uid 0 -gid 0 -print)" ] || return 1
    fi
}

astrax_sudoers_text() {
    astrax_helper_digest=$(sha256sum "$1" | cut -d ' ' -f 1)
    [ "${#astrax_helper_digest}" -eq 64 ] || return 1
    case "$astrax_helper_digest" in *[!0-9a-f]*) return 1 ;; esac
    printf 'astrax ALL=(root) NOPASSWD: NOSETENV: sha256:%s /opt/astrax/astrax-dvb-owners ""\n' "$astrax_helper_digest"
}

astrax_validate_sudoers() {
    "$1/usr/sbin/visudo" -cf "$2" >/dev/null || { echo 'DVB ownership sudoers validation failed' >&2; return 1; }
}

astrax_publish_file() {
    [ ! -e "$2" ] && [ ! -L "$2" ] || { echo "existing path: $2" >&2; return 1; }
    ln "$1" "$2" || return 1
    [ "$1" -ef "$2" ] && return 0
    # A directory raced the no-clobber link; remove only our accidental link.
    astrax_accidental="$2/$(basename "$1")"
    if [ "$1" -ef "$astrax_accidental" ]; then rm -f "$astrax_accidental"; fi
    echo "path changed during publication: $2" >&2
    return 1
}

astrax_preflight() {
    root=$1
    payload=$2
    [ "$root" != / ] || [ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; return 1; }
    for name in astrax MANIFEST.json lib/libastrax_srt.so.1.4.0 astrax-dvb-owners dvb-owner-helper share/build/dvb-owner-helper.sh; do
        [ -f "$payload/$name" ] && [ ! -L "$payload/$name" ] || { echo "incomplete verified payload: $name" >&2; return 1; }
    done
    cmp -s "$payload/dvb-owner-helper" "$payload/share/build/dvb-owner-helper.sh" || {
        echo 'DVB ownership launcher source mismatch' >&2; return 1
    }
    astrax_check_abi "$root" || return 1
    astrax_check_dvb_tools "$root" || return 1
    astrax_check_parent_paths "$root" || return 1
    init=$(astrax_detect_init "$root") || return 1
    astrax_check_release_target "$root" "$init" || return 1
    service=$(astrax_service_path "$root" "$init")
    for path in "$root/opt/astrax" "$root/var/lib/astrax" \
        "$root/etc/systemd/system/astrax.service" "$root/etc/init.d/astrax" \
        "$root/etc/sudoers.d/astrax-dvb-owners"; do
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
    if [ "${astrax_created_sudoers:-0}" -eq 1 ] && [ "$astrax_sudoers_stage" -ef "$astrax_sudoers" ]; then
        rm -f "$astrax_sudoers"
    fi
    if [ "${astrax_created_service:-0}" -eq 1 ] && [ "$astrax_service_stage" -ef "$astrax_service" ]; then
        rm -f "$astrax_service"
    fi
    [ -z "${astrax_sudoers_stage:-}" ] || rm -f "$astrax_sudoers_stage"
    [ -z "${astrax_stage:-}" ] || rm -rf "$astrax_stage"
    [ -z "${astrax_service_stage:-}" ] || rm -f "$astrax_service_stage"
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
    astrax_sudoers="$astrax_root/etc/sudoers.d/astrax-dvb-owners"
    astrax_created_account=0
    astrax_created_state=0
    astrax_created_runtime=0
    astrax_created_service=0
    astrax_created_sudoers=0
    astrax_service_stage=
    astrax_sudoers_stage=
    mkdir -p "$astrax_root/opt" || return 1
    astrax_stage=$(mktemp -d "$astrax_root/opt/.astrax-stage.XXXXXX") || return 1
    trap 'astrax_rollback' 0
    trap 'exit 1' 1 2 3 15
    cp -R "$payload/." "$astrax_stage/" || return 1
    mkdir -p "$astrax_root/etc/sudoers.d" || return 1
    astrax_sudoers_stage=$(mktemp "$astrax_root/etc/sudoers.d/.astrax-dvb-owners.XXXXXX") || return 1
    astrax_sudoers_text "$astrax_stage/astrax-dvb-owners" > "$astrax_sudoers_stage" || return 1
    chmod 440 "$astrax_sudoers_stage" || return 1
    if [ "$astrax_root" = / ]; then chown root:root "$astrax_sudoers_stage" || return 1; fi
    astrax_validate_sudoers "$astrax_root" "$astrax_sudoers_stage" || return 1
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
    mkdir -p "$astrax_root/var/lib" || return 1
    if [ "$astrax_root" != / ] && [ "${ASTRAX_TEST_RACE_CREATE_STATE:-}" = 1 ]; then
        mkdir "$astrax_root/var/lib/astrax" || return 1
        printf 'keep me' > "$astrax_root/var/lib/astrax/preexisting"
    fi
    mkdir "$astrax_root/var/lib/astrax" || return 1
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
    chmod 755 "$astrax_root/opt/astrax/astrax" "$astrax_root/opt/astrax/astrax-dvb-owners" \
        "$astrax_root/opt/astrax/dvb-owner-helper" || return 1
    if [ "$astrax_root" = / ]; then chown -R root:root "$astrax_root/opt/astrax" || return 1; fi
    rm -rf "$astrax_stage"
    astrax_stage=
    if [ "$astrax_root" != / ] && [ "${ASTRAX_TEST_FAIL_AFTER:-}" = runtime ]; then
        echo 'injected runtime failure' >&2
        return 1
    fi
    astrax_publish_file "$astrax_sudoers_stage" "$astrax_sudoers" || return 1
    astrax_created_sudoers=1
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
    if [ "$astrax_root" = / ]; then chown root:root "$astrax_service_stage" || return 1; fi
    astrax_publish_file "$astrax_service_stage" "$astrax_service" || return 1
    astrax_created_service=1
    if [ "$astrax_root" = / ] && [ "$astrax_init" = systemd ]; then systemctl daemon-reload || return 1; fi
    rm -f "$astrax_service_stage"
    astrax_service_stage=
    rm -f "$astrax_sudoers_stage"
    astrax_sudoers_stage=
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
    [ "${ASTRAX_PRIVATE_INSTALL_QA:-0}" != 1 ] || { echo 'private installer QA package cannot activate a service' >&2; return 1; }
    [ "$root" != / ] || [ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; return 1; }
    astrax_check_abi "$root" || return 1
    astrax_check_dvb_tools "$root" || return 1
    astrax_check_parent_paths "$root" || return 1
    init=$(astrax_detect_init "$root") || return 1
    astrax_check_release_target "$root" "$init" || return 1
    service=$(astrax_service_path "$root" "$init")
    template_dir=${ASTRAX_TEMPLATE_DIR:-}
    [ -f "$template_dir/$init.in" ] && [ -f "$service" ] || { echo 'service definition missing' >&2; return 1; }
    for name in astrax astrax-dvb-owners dvb-owner-helper MANIFEST.json lib/libastrax_srt.so.1.4.0; do
        case "$name" in astrax|astrax-dvb-owners|dvb-owner-helper) mode=755 ;; *) mode=644 ;; esac
        astrax_secure_file "$root" "$root/opt/astrax/$name" "$mode" || return 1
        cmp -s "$root/opt/astrax/$name" "$payload/$name" || {
            echo "installed $name does not match this package" >&2
            return 1
        }
    done
    astrax_secure_directory "$root" "$root/opt/astrax" || return 1
    astrax_secure_directory "$root" "$root/opt/astrax/lib" || return 1
    [ "$(readlink "$root/opt/astrax/lib/libastrax_srt.so.1" 2>/dev/null)" = libastrax_srt.so.1.4.0 ] || {
        echo 'installed SRT SONAME link mismatch' >&2; return 1
    }
    cmp -s "$service" "$template_dir/$init.in" || { echo 'service definition mismatch' >&2; return 1; }
    if [ "$init" = systemd ]; then mode=644; else mode=755; fi
    astrax_secure_file "$root" "$service" "$mode" || return 1
    astrax_secure_file "$root" "$root/etc/sudoers.d/astrax-dvb-owners" 440 || return 1
    expected=$(astrax_sudoers_text "$payload/astrax-dvb-owners" | sha256sum | cut -d ' ' -f 1)
    actual=$(sha256sum "$root/etc/sudoers.d/astrax-dvb-owners" | cut -d ' ' -f 1)
    [ "$actual" = "$expected" ] || { echo 'installed DVB ownership sudoers mismatch' >&2; return 1; }
    astrax_validate_sudoers "$root" "$root/etc/sudoers.d/astrax-dvb-owners" || return 1
    [ -d "$root/var/lib/astrax" ] || { echo 'state directory missing' >&2; return 1; }
    [ "$(astrax_account_status "$root")" = compatible ] || {
        echo 'compatible astrax account required for activation' >&2
        return 1
    }
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
    echo 'AstraX service enable/start command succeeded; verify service health before use'
    echo 'Default management: http://127.0.0.1:8080 (local to the host; configured address may differ).'
    echo 'For remote administration, use a private SSH tunnel to the host loopback address.'
    echo '  ssh -L 8080:127.0.0.1:8080 USER@HOST'
    echo 'Before first enrollment, read the owner-only setup file locally as root:'
    echo '  /var/lib/astrax/astrax-config.json.admin-setup'
    echo 'Enter its one-time secret in the setup page and set the named admin account password; the installer never prints the secret.'
    echo 'Sign in as admin with your username and password. Use Users to manage Administrator, Operator and Viewer roles.'
}

if [ "${ASTRAX_CORE_LIBRARY_ONLY:-}" = 1 ]; then
    return 0
fi

case ${1-} in
    --install) [ "$#" -eq 2 ] || exit 2; astrax_install / "$2" ;;
    --activate) [ "$#" -eq 2 ] || exit 2; astrax_activate / "$2" ;;
    *) echo 'invalid installer core command' >&2; exit 2 ;;
esac
