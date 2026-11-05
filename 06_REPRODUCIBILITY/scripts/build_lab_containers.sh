#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="${LAB_ROOT:-$HOME/lab}"

if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    LAB_ROOT="$REAL_HOME/lab"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }

need docker
need gcc
need ldd
need readelf
need curl
need python3

echo "[1/5] Building static HTTP server..."
gcc -O2 -static "$ROOT/server/http_server.c" -o "$ROOT/server/http_server"

echo "[2/5] Preparing local curl image payload..."
rm -rf "$ROOT/client/libs"
mkdir -p "$ROOT/client/libs"
cp "$(command -v curl)" "$ROOT/client/curl"

ldd "$(command -v curl)" |
awk '/=> \// {print $3} /^\// {print $1}' |
sort -u |
while read -r lib; do
    [[ -f "$lib" ]] || continue
    dest="$ROOT/client/libs$lib"
    mkdir -p "$(dirname "$dest")"
    cp -L "$lib" "$dest"
done

interp="$(readelf -l "$(command -v curl)" | awk -F': ' '/Requesting program interpreter/ {print $2}' | tr -d ']')"
if [[ -n "$interp" && -f "$interp" ]]; then
    dest="$ROOT/client/libs$interp"
    mkdir -p "$(dirname "$dest")"
    cp -L "$interp" "$dest"
fi

echo "[3/5] Preparing target binaries..."
[[ -x "$LAB_ROOT/bin/procfd_exec_test" ]] || {
    echo "Missing $LAB_ROOT/bin/procfd_exec_test. Run run_lab.sh once first." >&2
    exit 1
}
[[ -f "$LAB_ROOT/bin/libpreload_test.so" ]] || {
    echo "Missing $LAB_ROOT/bin/libpreload_test.so. Run run_lab.sh once first." >&2
    exit 1
}

cp "$LAB_ROOT/bin/procfd_exec_test" "$ROOT/target/procfd_exec_test"
cp "$LAB_ROOT/bin/libpreload_test.so" "$ROOT/target/libpreload_test.so"

echo "[4/5] Preparing local Python runtime..."
rm -rf "$ROOT/target/python_lib" "$ROOT/target/python_lib_version" "$ROOT/target/python_site" "$ROOT/target/python_libs"
mkdir -p "$ROOT/target/python_lib" "$ROOT/target/python_lib_version" "$ROOT/target/python_site" "$ROOT/target/python_libs"

PY="$(readlink -f "$(command -v python3)")"
cp "$PY" "$ROOT/target/python3"

# Copy Python shared-library dependencies.
ldd "$PY" |
awk '/=> \// {print $3} /^\// {print $1}' |
sort -u |
while read -r lib; do
    [[ -f "$lib" ]] || continue
    dest="$ROOT/target/python_libs$lib"
    mkdir -p "$(dirname "$dest")"
    cp -L "$lib" "$dest"
done

interp="$(readelf -l "$PY" | awk -F': ' '/Requesting program interpreter/ {print $2}' | tr -d ']')"
if [[ -n "$interp" && -f "$interp" ]]; then
    dest="$ROOT/target/python_libs$interp"
    mkdir -p "$(dirname "$dest")"
    cp -L "$interp" "$dest"
fi

# Ubuntu's Python standard library.
PY_MAJOR_MINOR="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_STD="$(python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')"
PY_SITE="$(python3 -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"

[[ -d "$PY_STD" ]] || { echo "Cannot locate Python stdlib: $PY_STD" >&2; exit 1; }
cp -a "$PY_STD/." "$ROOT/target/python_lib_version/"

if [[ -d "$PY_SITE" ]]; then
    cp -a "$PY_SITE/." "$ROOT/target/python_site/" 2>/dev/null || true
fi

echo "Python version: $PY_MAJOR_MINOR"

echo "[5/5] Building 3 images..."
docker build -t falco-lab-server:latest "$ROOT/server"
docker build -t falco-lab-client:latest "$ROOT/client"
docker build -t falco-lab-target:latest "$ROOT/target"

echo
echo "=== LOCAL LAB IMAGES ==="
docker image ls --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' |
grep -E '^falco-lab-(server|client|target)\s' || true
