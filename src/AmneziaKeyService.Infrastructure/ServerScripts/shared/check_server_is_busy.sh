#!/usr/bin/env bash
# Contract for the installer: 0 = ready, 1 = package manager is busy,
# 2 = the state could not be determined safely.

probe_error() {
    printf '%s\n' "$1" >&2
    exit 2
}

# fuser returns 0 when at least one of the files is in use and 1 when none
# are in use. Do not leak that implementation detail to the caller.
probe_fuser() {
    command -v fuser >/dev/null 2>&1 || probe_error "Package-lock probe requires fuser"
    fuser -s "$@" >/dev/null 2>&1
    local status=$?

    case "$status" in
        0) exit 1 ;;
        1) exit 0 ;;
        *) probe_error "Package-lock probe failed (fuser exit $status)" ;;
    esac
}

# yum and zypper publish a PID file rather than a lock file suitable for
# fuser. A stale PID file must not keep the installer waiting forever.
probe_pid_file() {
    local pid_file="$1"
    local pid

    [[ -e "$pid_file" ]] || exit 0
    read -r pid < "$pid_file" || probe_error "Cannot read package-manager PID file"
    [[ "$pid" =~ ^[0-9]+$ ]] || probe_error "Invalid package-manager PID file"

    kill -0 "$pid" 2>/dev/null
    local status=$?
    case "$status" in
        0) exit 1 ;;
        1) exit 0 ;;
        *) probe_error "Cannot inspect package-manager process" ;;
    esac
}

if command -v apt-get >/dev/null 2>&1; then
    probe_fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
elif command -v dnf >/dev/null 2>&1; then
    shopt -s nullglob
    dnf_locks=(/var/cache/dnf/* /var/run/dnf/* /var/lib/dnf/* /var/lib/rpm/*)
    ((${#dnf_locks[@]} > 0)) || exit 0
    probe_fuser "${dnf_locks[@]}"
elif command -v yum >/dev/null 2>&1; then
    probe_pid_file /var/run/yum.pid
elif command -v zypper >/dev/null 2>&1; then
    probe_pid_file /var/run/zypp.pid
elif command -v pacman >/dev/null 2>&1; then
    probe_fuser /var/lib/pacman/db.lck
else
    probe_error "Package manager not found"
fi
