#!/usr/bin/env bash

set -euo pipefail
trap 'fatal "Error on line $LINENO"' ERR

source "$(dirname "$0")/vars.sh"

MEM="${VM_MEM:-64G}"
SHARED="$WORK_DIR"

SOCK="$RESULT_DIR/bpf-test.sock"
VIRTIOFSD_LOG="$RESULT_DIR/virtiofsd.log"
VM_PIDFILE="$RESULT_DIR/vm.pid"
VM_LOG="$RESULT_DIR/vm.log"

require() { [[ -f "$1" ]] || fatal "$2 not found"; }
require "$VM_IMG" "VM image"
require "$VM_FSD" "virtiofsd"
require "$KERNEL_PATH" "Kernel"
command -v qemu-system-x86_64 >/dev/null 2>&1 || fatal "qemu-system-x86_64 not found in PATH"

wait_for() {
    local what="$1" file="$2" max="$3" check="[[ -e \$file ]]"
    for ((i=1; i<=max; i++)); do
        eval "$check" && return 0
        sleep 1
    done
    fatal "$what did not appear: $file"
}

rm -f "$SOCK" "$VM_PIDFILE" "$VIRTIOFSD_LOG" "$VM_LOG"

ack "Starting virtiofsd..."
"$VM_FSD" --socket-path "$SOCK" --shared-dir "$SHARED" > "$VIRTIOFSD_LOG" 2>&1 &

wait_for "virtiofsd socket" "$SOCK" 5
[[ -S "$SOCK" ]] || fatal "virtiofsd did not create socket $SOCK"

ack "Launching QEMU VM..."
qemu-system-x86_64 \
    -m "$MEM" \
    -smp $(nproc) \
    -kernel "$KERNEL_PATH" \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 panic_on_warn=0" \
    -drive file="$VM_IMG",format=raw \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:"$VM_SSH_PORT"-:22 \
    -net nic,model=e1000 \
    -enable-kvm \
    -nographic \
    -pidfile "$VM_PIDFILE" \
    -object memory-backend-file,id=mem,size="$MEM",mem-path=/dev/shm,share=on \
    -numa node,memdev=mem \
    -chardev socket,id=char0,path="$SOCK" \
    -device vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=bpf-test \
    -snapshot \
    > "$VM_LOG" 2>&1 &

wait_for "QEMU PID file" "$VM_PIDFILE" 10

ack "VM started, waiting for it to boot..."
for ((i=1; i<=120; i++)); do
    echo -ne "\rWaiting for VM to boot $i/120 (s)..."
    if _vmcmd "pwd" > /dev/null 2>&1; then
        echo
        ack "VM started. SSH will be available on port $VM_SSH_PORT."
        _vmcmd "mount -t virtiofs bpf-test ${VM_BCF_DIR}" || fatal "Failed to mount virtiofs at ${VM_BCF_DIR}"
        ack "Shared directory mounted: ${WORK_DIR} => ${VM_BCF_DIR}"
        exit 0
    fi
    sleep 1
done

fatal "VM did not become available via SSH on port $VM_SSH_PORT"
