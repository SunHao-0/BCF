#!/bin/bash

set -euo pipefail
trap 'fatal "Error on line $LINENO"' ERR

source "$(dirname "$0")/vars.sh"

help() {
    echo "Usage: $0 [--run-bench | --run-load | --analyze | --help]"
    echo "  --run-bench: Run benchmarks"
    echo "  --run-load: Run load exp"
    echo "  --analyze: Analyze the results"
    exit 0
}

check_resources() {
    local mem_required=256
    local mem_available=$(free -g | awk '/^Mem:/ {print $2}')
    if [[ $mem_available -lt $mem_required ]]; then
        fatal "At least $mem_requiredG of memory is required, but only $mem_availableG is available"
    fi
}

require_file() {
    [[ -f "$1" ]] || fatal "$2 not found at $1"
}

run_exp() {
    check_resources

    # Check required files
    require_file "$KERNEL_PATH" "Kernel"
    require_file "$BPFTOOL_PATH" "bpftool"
    require_file "$SOLVER_PATH/bin/cvc5" "cvc5"
    require_file "${PROG_DIR}/prog_index.json" "prog_index.json"

    # stop the vm if it is running
    if [[ -f "$VM_PIDFILE" ]]; then
        vmstop
    fi

    $SCRIPT_DIR/boot_vm.sh || fatal "Failed to boot VM"
    ack "VM booted"

    extra_args=()
    [[ "$RUN_BENCHMARKS" == true ]] && extra_args+=(--bench)

    # do not cache python print output
    _vmcmd "cd ${VM_BCF_DIR} && python3 -u ./scripts/load_prog.py ${extra_args[*]} --directory ${VM_PROG_DIR} \
            --output ${VM_RESULT_DIR} --bpftool ${VM_BPF_TOOL_PATH} > ${VM_RESULT_DIR}/load.log 2>&1" &
    LOAD_PID=$!

    # Wait for load.log to appear, or process exit
    while ! [[ -f "${RESULT_DIR}/load.log" ]]; do
        if ! kill -0 $LOAD_PID 2>/dev/null; then
            fatal "load_prog.py process exited before creating load.log"
            vmstop
            exit 1
        fi
        info "Waiting for load_prog.py running..."
        sleep 2
    done

    ack "exp booted, check ${RESULT_DIR}/load.log for details"
    ack "stop the vm after the exp by running: 'kill -9 $LOAD_PID'"
}

analyze_exp() {
    $SCRIPT_DIR/process_bcf_result.py --output_dir ${RESULT_DIR} -p ${PROG_DIR}
}


RUN_BENCHMARKS=false
case "${1:-}" in
    --run-bench) RUN_BENCHMARKS=true; run_exp ;;
    --run-load) run_exp ;;
    --analyze) analyze_exp ;;
    --help) help ;;
    *) help ;;
esac
