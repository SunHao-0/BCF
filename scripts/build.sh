#!/usr/bin/env bash

set -euo pipefail

source "$(dirname "$0")/vars.sh"

LOGFILE="$BUILD_DIR/build.log"
: > "$LOGFILE"

trap 'echo -e "\033[0;31m[-] Error on line $LINENO\033[0m"; echo "Error on line $LINENO" >> "$LOGFILE"; exit 1' ERR

download_if_missing() {
    local url="$1" dest="$2"
    [[ -f "$dest" ]] && return
    do_log "Downloading $(basename "$dest")"
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

patch_loader_paths() {
    local dir="$1"
    for patch in "$dir"/0004-bpftool-Check-cvc5-prover-feature.patch "$dir"/0006-bpftool-Add-cvc5-prover-support.patch; do
        [[ -f "$patch" ]] || continue
        sed -i "s|{REPLACE_INC}|$SOLVER_PATH/include|g" "$patch" >>"$LOGFILE" 2>&1
        sed -i "s|{REPLACE_LIB}|$SOLVER_PATH/lib|g" "$patch" >>"$LOGFILE" 2>&1
    done
}

build_kernel() {
    local kernel_dir="$BUILD_DIR/$KERNEL_NAME"
    local kernel_tar="$BUILD_DIR/$KERNEL_TAR"
    local kernel_url="https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.13.4.tar.xz"
    local loader_skips=("0000-cover-letter.patch" "0001-bpf-Add-bcf-uapi-arguments.patch" "0002-bpf-Add-bcf-expression-and-formula-definitions.patch")
    local kernel_skips=("0000-cover-letter.patch")

    if [[ -d "$kernel_dir" || -f "$KERNEL_PATH" ]]; then
        do_log "Kernel already built, skipping"
        return
    fi

    [[ -f "$SOLVER_PATH/bin/cvc5" ]] || fatal "Solver must be built and installed first"

    download_if_missing "$kernel_url" "$kernel_tar"
    ack "Extracting kernel tarball"
    tar -xf "$kernel_tar" -C "$BUILD_DIR" >>"$LOGFILE" 2>&1 || fatal "Failed to extract $kernel_tar (see $LOGFILE)"

    pushd "$kernel_dir" > /dev/null

    ack "Applying kernel patches"
    apply_patches "$KERNEL_PATCH_DIR" kernel_skips[@]

    ack "Applying loader patches"

    local loader_patches_dir="$BUILD_DIR/patches-loader"
    mkdir -p "$loader_patches_dir"
    cp "$LAODER_PATCH_DIR"/*.patch "$loader_patches_dir"
    patch_loader_paths "$loader_patches_dir"

    apply_patches "$loader_patches_dir" loader_skips[@]

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
    local solver_url="https://github.com/cvc5/cvc5/archive/8514715cbc48f898f620955f8c718495f926777d.zip"
    local solver_skips=("cvc5.patch")

    if [[ -d "$solver_dir" || -f "$SOLVER_PATH" ]]; then
        do_log "Solver already built, skipping"
        return
    fi

    download_if_missing "$solver_url" "$solver_tar"
    unzip -q "$solver_tar" -d "$BUILD_DIR" >>"$LOGFILE" 2>&1 || fatal "Failed to unzip $solver_tar (see $LOGFILE)"
    [[ -d "$solver_dir" ]] || mv "$BUILD_DIR/$SOLVER_NAME" "$solver_dir" 2>/dev/null || true

    pushd "$solver_dir" > /dev/null
    ack "Applying solver patches"
    apply_patches "$SOLVER_PATCH_DIR" solver_skips[@]

    ack "Building solver..."
    ./configure.sh --best --gpl --auto-download --prefix="$SOLVER_PATH" >>"$LOGFILE" 2>&1 || fatal "Solver configure failed (see $LOGFILE)"
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
