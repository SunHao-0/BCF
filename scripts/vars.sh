# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

log() {
    local level=$1
    local msg=$2
    local prefix="[$(date "+%Y/%m/%d @ %H:%M:%S")]"

    case $level in
        BLUE)   echo -e "[*]$prefix ${BLUE}${msg}${RESET}" ;;
        GREEN)  echo -e "[+]$prefix ${GREEN}${msg}${RESET}" ;;
        ORANGE) echo -e "[!]$prefix ${ORANGE}${msg}${RESET}" ;;
        RED)    echo -e "[-]$prefix ${RED}${msg}${RESET}" >&2; exit 1 ;;
    esac
}

info()  { log "BLUE" "$1"; }
ack()   { log "GREEN" "$1"; }
warn()  { log "ORANGE" "$1"; }
fatal() { log "RED" "$1"; }

export WORK_DIR="$PWD"
export SCRIPT_DIR="$WORK_DIR/scripts"
export IMG_DIR="$WORK_DIR/imgs"
export PROG_DIR="$WORK_DIR/bpf-progs"
export KERNEL_PATCH_DIR="$WORK_DIR/patches-kernel"
export LAODER_PATCH_DIR="$WORK_DIR/patches-loader"
export SOLVER_PATCH_DIR="$WORK_DIR/patches-solver"

for dir in "$KERNEL_PATCH_DIR" "$LAODER_PATCH_DIR" "$SOLVER_PATCH_DIR" "$SCRIPT_DIR" "$PROG_DIR"; do
    [[ -d "$dir" ]] || fatal "Directory $dir not found"
done

export BUILD_DIR="$WORK_DIR/build"
export RESULT_DIR="$WORK_DIR/output"
for dir in "$BUILD_DIR" "$RESULT_DIR"; do
    mkdir -p "$dir"
done

export KERNEL_NAME=linux-6.13.4
export KERNEL_TAR=linux-6.13.4.tar.gz
export SOLVER_NAME=cvc5-8514715cbc48f898f620955f8c718495f926777d
export SOLVER_TAR=cvc5-8514715cbc48f898f620955f8c718495f926777d.zip
export KERNEL_CONFIG=$SCRIPT_DIR/kernel-config
export KERNEL_PATH=$RESULT_DIR/bzImage
export BPFTOOL_PATH=$RESULT_DIR/bpftool
export SOLVER_PATH=$RESULT_DIR/cvc5-libs

# The root testing directory in the VM
export VM_BCF_DIR="/root/bcf"
export VM_PIDFILE="$RESULT_DIR/vm.pid"
export VM_IMG_DIR=$IMG_DIR
export VM_IMG=$VM_IMG_DIR/bookworm.img
export VM_SSHKEY=$VM_IMG_DIR/bookworm.id_rsa
export VM_PUBKEY=${VM_SSHKEY}.pub
export VM_SSH_PORT=10023
export VM_BUILD_DIR="$VM_BCF_DIR/build"
export VM_SCRIPT_DIR="$VM_BCF_DIR/scripts"
export VM_RESULT_DIR="$VM_BCF_DIR/output"
export VM_KERNEL_PATCH_DIR="$VM_BCF_DIR/patches-kernel"
export VM_LAODER_PATCH_DIR="$VM_BCF_DIR/patches-loader"
export VM_SOLVER_PATCH_DIR="$VM_BCF_DIR/patches-solver"
export VM_PROG_DIR="$VM_BCF_DIR/bpf-progs"
export VM_BPF_TOOL_PATH="$VM_RESULT_DIR/bpftool"

# ensure virtiofsd is in PATH
command -v virtiofsd >/dev/null 2>&1 || fatal "virtiofsd not found in PATH"
export VM_FSD=`which virtiofsd`

# SSH command wrapper
_vmcmd() {
    ssh -i "${VM_SSHKEY}" -p "${VM_SSH_PORT}" \
        -o UserKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=1 -q root@localhost "$@"
}


vmcmd() {
    local oldstate=$(set +o)
    set +eu
    _vmcmd "$@"
    eval "$oldstate"
}

vmstop() {
    _vmcmd "shutdown -h now"
    rm -f ${VM_PIDFILE}
    rm -f ${RESULT_DIR}/bpf-test.sock ${RESULT_DIR}/bpf-test.sock.pid
    ack "Stopped VM."
}
