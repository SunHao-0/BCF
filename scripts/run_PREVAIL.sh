#!/bin/bash

source "$(dirname "$0")/vars.sh"

# Global flag to control script execution
PREVAIL_DIR="${BUILD_DIR}/prevail"
mkdir -p "$PREVAIL_DIR"

PREVAIL="${PREVAIL_DIR}/ebpf-verifier/check"
OUTPUT_FILE="${RESULT_DIR}/PREVAIL_load_results.log"
PROGRAMS_FILE="${RESULT_DIR}/PREVAIL_programs"
PREVAIL_LOAD_LOG="${RESULT_DIR}/PREVAIL_load.log"

rm -f "$OUTPUT_FILE" "$PROGRAMS_FILE" "$PREVAIL_LOAD_LOG"

STOP_REQUESTED=false
cleanup() {
    info "Stopping PREVAIL script..."
    STOP_REQUESTED=true
    pkill -9 -f "$PREVAIL" 2>/dev/null || true
    # Also kill any background processes from this script
    # pkill -P $$ 2>/dev/null || true
}
trap cleanup SIGINT SIGTERM

build_prevail() {
    pushd "$PREVAIL_DIR" >/dev/null

    if [[ -d "ebpf-verifier" ]]; then
        rm -rf "ebpf-verifier"
    fi

    if ! git clone --recurse-submodules https://github.com/vbpf/ebpf-verifier.git; then
        fatal "Failed to clone ebpf-verifier"
    fi
    pushd "ebpf-verifier" >/dev/null
    if ! git checkout 880008addbb6e4bf2a35fe875ec20b1079144cc3; then
        fatal "Failed to checkout PREVAIL commit"
    fi
    if ! cmake -B build -DCMAKE_BUILD_TYPE=Release; then
        fatal "CMake failed for PREVAIL"
    fi
    if ! make -C build -j"$(nproc)"; then
        fatal "Make failed for PREVAIL"
    fi
    popd >/dev/null
    popd >/dev/null
}

if [[ ! -f "$PREVAIL" ]]; then
    ack "Building PREVAIL..."
    build_prevail
fi

#  Collects programs that the PREVAIL verifier is able to verify
#
# For each object, first executes "check -l obj.bpf.o" to see if it can load the ELF file; if not, skips the object.
# The output of listed programs follows the format: [section=... function=...], for example:
#   section=cgroup/post_bind4 function=cil_sock4_post_bind
#   section=cgroup/sendmsg4 function=cil_sock4_sendmsg
#   section=cgroup/recvmsg4 function=cil_sock4_recvmsg
#   section=cgroup/post_bind6 function=cil_sock6_post_bind
#   section=cgroup/connect6 function=cil_sock6_connect
#   section=cgroup/sendmsg6 function=cil_sock6_sendmsg
#   section=cgroup/recvmsg6 function=cil_sock6_recvmsg
# Then, for each section listed, executes "check obj.bpf.o section function" to see if it can verify the program. For example:
#   check obj.bpf.o cgroup/post_bind4 cil_sock4_post_bind
# The result follows the format: 1/0 (pass/failed), runtime, mem usage. For example:
#   1,0.008288,4064

ack "Checking $(find "$PROG_DIR" -name "*.o" | wc -l) objects with PREVAIL"
objs=$(find "$PROG_DIR" -name "*.o")
if [[ -z "$objs" ]]; then
    warn "No .o files found in $PROG_DIR"
    exit 0
fi

for obj in $objs; do
    echo "Checking $obj"
    # Check if stop was requested
    if [[ "$STOP_REQUESTED" == "true" ]]; then
        echo "Stop requested, exiting loop"
        break
    fi

    base_name=$(basename "$obj")
    info "Checking $base_name..."

    # Use a unique programs file per object to avoid overwriting
    obj_programs_file="${PROGRAMS_FILE}.${base_name}"
    if ! "$PREVAIL" -l "$obj" > "$obj_programs_file" 2>&1; then
        warn "$base_name: compat"
        echo "$base_name, compat" >> "$OUTPUT_FILE"
        rm -f "$obj_programs_file"
        continue
    fi

    # read each line of programs.txt, and trim the line to get the section name
    while IFS= read -r program; do
        # Check if stop was requested
        if [[ "$STOP_REQUESTED" == "true" ]]; then
            echo "Stop requested, exiting inner loop"
            break 2
        fi

        section=$(echo "$program" | awk -F'[ =]' '{print $2}')
        function=$(echo "$program" | awk -F'[ =]' '{print $4}')

        if [[ -z "$section" || -z "$function" ]]; then
            continue
        fi

        info "    Checking $section/$function"

        tmp_result_file=$(mktemp)
        timeout 1000 "$PREVAIL" "$obj" "$section" "$function" > "$tmp_result_file" 2>&1
        exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            echo "$base_name, $section/$function, timeout" >> "$OUTPUT_FILE"
            warn "    timeout"
            rm -f "$tmp_result_file"
            continue
        fi

        result=$(<"$tmp_result_file")
        info "    $result"
        echo "$base_name, $section/$function, result:$result" >> "$OUTPUT_FILE"
        rm -f "$tmp_result_file"
    done < "$obj_programs_file"
    rm -f "$obj_programs_file"
done

if [[ "$STOP_REQUESTED" == "true" ]]; then
    info "Stopped by request"
else
    info "Completed"
fi
