#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/vars.sh"

LOGFILE="$BUILD_DIR/build.log"
: > "$LOGFILE"

trap 'echo -e "\033[0;31m[-] Error on line $LINENO\033[0m"; echo "Error on line $LINENO" >> "$LOGFILE"; exit 1' ERR

download_if_missing() {
    local url="$1" dest="$2"
    [[ -f "$dest" ]] && return
    info "Downloading $(basename "$dest")"
    curl -L -o "$dest" "$url" >>"$LOGFILE" 2>&1 || fatal "Failed to download $url (see $LOGFILE)"
}

apply_patches() {
    local dir="$1" skip=("${!2}")
    for patch in "$dir"/*.patch; do
        local name=$(basename "$patch")
        [[ " ${skip[*]} " =~ " $name " ]] && continue
        patch -p1 < "$patch" >>"$LOGFILE" 2>&1 || fatal "Failed to apply patch $patch (see $LOGFILE)"
    done
}

build_kernel() {
    local kernel_dir="$KERNEL_SRC_DIR"
    local set_skips=("0000-cover-letter.patch")

    if [[ -f "$KERNEL_PATH" ]]; then
        info "Kernel already built, skipping"
        return
    fi

    if [[ -d "$kernel_dir" ]]; then
        ack "Removing existing kernel source at $kernel_dir"
        rm -rf "$kernel_dir" >>"$LOGFILE" 2>&1 || fatal "Failed to remove $kernel_dir (see $LOGFILE)"
    fi

    if [[ -n "$BPF_NEXT_COMMIT" ]]; then
        ack "Cloning bpf-next and checking out $BPF_NEXT_COMMIT"
        git clone "$BPF_NEXT_REPO_URL" "$kernel_dir" >>"$LOGFILE" 2>&1 || fatal "Failed to clone $BPF_NEXT_REPO_URL (see $LOGFILE)"
        pushd "$kernel_dir" > /dev/null
        git checkout -q "$BPF_NEXT_COMMIT" >>"$LOGFILE" 2>&1 || fatal "Failed to checkout commit $BPF_NEXT_COMMIT (see $LOGFILE)"
    else
        ack "Cloning bpf-next"
        git clone "$BPF_NEXT_REPO_URL" "$kernel_dir" >>"$LOGFILE" 2>&1 || fatal "Failed to clone $BPF_NEXT_REPO_URL (see $LOGFILE)"
        pushd "$kernel_dir" > /dev/null
    fi

    pushd "$kernel_dir" > /dev/null

    ack "Applying kernel patches (set1..set5)"
    for setdir in \
        "$KERNEL_PATCH_DIR/set1:verifier_and_initial_checker_support" \
        "$KERNEL_PATCH_DIR/set2:add_core_proof_rules" \
        "$KERNEL_PATCH_DIR/set3:add_boolean_proof_rules" \
        "$KERNEL_PATCH_DIR/set4:add_bv_proof_rules" \
        "$KERNEL_PATCH_DIR/set5:bpftool_libbpf_support"; do
        [[ -d "$setdir" ]] || fatal "Patch set directory $setdir not found"
        apply_patches "$setdir" set_skips[@]
    done

    ack "Configuring kernel..."
    cp "$KERNEL_CONFIG" .config >>"$LOGFILE" 2>&1 || fatal "Failed to copy kernel config (see $LOGFILE)"
    cat tools/testing/selftests/bpf/config tools/testing/selftests/bpf/config.x86_64 tools/testing/selftests/bpf/config.vm >> .config 2>>"$LOGFILE" || fatal "Failed to append kernel configs (see $LOGFILE)"
    make olddefconfig >>"$LOGFILE" 2>&1 || fatal "make olddefconfig failed (see $LOGFILE)"

    for cfg in CONFIG_BPF_SYSCALL CONFIG_BPF_JIT_ALWAYS_ON; do
        grep -q "${cfg}=y" .config || fatal "$cfg is not enabled"
    done

    ack "Building kernel..."
    make -j"$(nproc)" >>"$LOGFILE" 2>&1 || fatal "Kernel build failed (see $LOGFILE)"
    [[ -f arch/x86/boot/bzImage ]] || fatal "Kernel image not found"
    cp arch/x86/boot/bzImage "$KERNEL_PATH" >>"$LOGFILE" 2>&1 || fatal "Failed to copy bzImage (see $LOGFILE)"

    ack "Building loader tool..."
    make -C tools/bpf/bpftool -j8 >>"$LOGFILE" 2>&1 || fatal "Loader tool build failed (see $LOGFILE)"
    [[ -f tools/bpf/bpftool/bpftool ]] || fatal "Loader tool not found"
    cp tools/bpf/bpftool/bpftool "$BPFTOOL_PATH" >>"$LOGFILE" 2>&1 || fatal "Failed to copy bpftool (see $LOGFILE)"

    popd > /dev/null
}

build_solver() {
    local solver_tar="$BUILD_DIR/$SOLVER_TAR"
    local solver_dir="$BUILD_DIR/$SOLVER_NAME"
    local solver_url="https://github.com/cvc5/cvc5/archive/${SOLVER_COMMIT}.zip"
    local solver_skips=("cvc5.patch")

    if [[ -d "$solver_dir" || -f "$SOLVER_PATH" ]]; then
        info "Solver already built, skipping"
        return
    fi

    download_if_missing "$solver_url" "$solver_tar"
    unzip -q "$solver_tar" -d "$BUILD_DIR" >>"$LOGFILE" 2>&1 || fatal "Failed to unzip $solver_tar (see $LOGFILE)"
    [[ -d "$solver_dir" ]] || mv "$BUILD_DIR/$SOLVER_NAME" "$solver_dir" 2>/dev/null || true

    pushd "$solver_dir" > /dev/null
    ack "Applying solver patches"
    apply_patches "$SOLVER_PATCH_DIR" solver_skips[@]

    ack "Building solver..."
    ./configure.sh --best --static --gpl --auto-download --prefix="$SOLVER_PATH" >>"$LOGFILE" 2>&1 || fatal "Solver configure failed (see $LOGFILE)"
    make -C build -j"$(nproc)" >>"$LOGFILE" 2>&1 || fatal "Solver build failed (see $LOGFILE)"
    make -C build install >>"$LOGFILE" 2>&1 || fatal "Solver install failed (see $LOGFILE)"
    [[ -f "$SOLVER_PATH/bin/cvc5" ]] || fatal "Solver not found"
    popd > /dev/null
}

usage() {
    echo "Usage: $0 kernel|solver|all"
    exit 1
}

main() {
    [[ $# -eq 1 ]] || usage
    case "$1" in
        kernel) build_kernel ;;
        solver) build_solver ;;
        all) build_solver; build_kernel ;;
        *) echo "Unknown target: $1"; usage ;;
    esac
}

main "$@"
