#!/usr/bin/env bash

set -euo pipefail
trap 'fatal "Error on line $LINENO"' ERR

source "$(dirname "$0")/vars.sh"

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif command -v lsb_release &>/dev/null; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [[ -f /etc/debian_version ]]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [[ -f /etc/SuSe-release ]]; then
        OS=SuSE
        VER=""
    elif [[ -f /etc/redhat-release ]]; then
        OS=RedHat
        VER=""
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
}

install_packages() {
    local packages=("$@")
    if command -v apt-get &>/dev/null; then
        info "Using apt-get"
        [[ -z "${APT_UPDATED:-}" ]] && sudo apt-get update && APT_UPDATED=1
        sudo apt-get install -y "${packages[@]}"
    elif command -v yum &>/dev/null; then
        info "Using yum"
        sudo yum install -y "${packages[@]}"
    elif command -v dnf &>/dev/null; then
        info "Using dnf"
        sudo dnf install -y "${packages[@]}"
    elif command -v pacman &>/dev/null; then
        info "Using pacman"
        sudo pacman -S --noconfirm "${packages[@]}"
    elif command -v brew &>/dev/null; then
        info "Using Homebrew"
        brew install "${packages[@]}"
    else
        fatal "No supported package manager found"
    fi
}

command_exists() { command -v "$1" &>/dev/null; }

install_python_deps() {
    info "Installing Python dependencies..."
    if ! command_exists pip3; then
        warn "pip3 not found, installing..."
        if command_exists apt-get; then
            sudo apt-get install -y python3-pip
        elif command_exists yum; then
            sudo yum install -y python3-pip
        elif command_exists dnf; then
            sudo dnf install -y python3-pip
        elif command_exists pacman; then
            sudo pacman -S --noconfirm python-pip
        elif command_exists brew; then
            brew install python3
        else
            fatal "Could not install pip3: no supported package manager found"
        fi
    fi
    local python_packages=(numpy matplotlib scipy seaborn prettytable pandas)
    for pkg in "${python_packages[@]}"; do
        python3 -c "import $pkg" &>/dev/null \
            && ack "Python package $pkg already installed" \
            || { info "Installing Python package: $pkg"; pip3 install --user "$pkg"; }
    done
}

install_kernel_deps() {
    info "Installing kernel build dependencies..."
    install_packages build-essential libncurses5-dev libssl-dev libelf-dev flex bison pkg-config \
        libpcap-dev libcap-dev bc rsync unzip patch
}

install_solver_deps() {
    info "Installing CVC5 solver build dependencies..."
    install_packages build-essential cmake python3 python3-pip libgmp-dev libboost-all-dev \
        libreadline-dev libedit-dev libffi-dev libssl-dev pkg-config autoconf automake libtool \
        git wget curl unzip
}

install_vm_deps() {
    info "Installing VM/virtualization dependencies..."
    install_packages qemu-system-x86 qemu-utils ssh openssh-client openssh-server
    if ! command_exists rustup; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    if ! command_exists virtiofsd; then
        # source: https://gitlab.com/virtio-fs/virtiofsd
        cargo install virtiofsd &>/dev/null || fatal "Failed to install virtiofsd"
        ack "Installed virtiofsd"
    fi
}

install_prevail_deps() {
    info "Installing PREVAIL build dependencies..."
    install_packages build-essential git cmake libboost-dev libyaml-cpp-dev \
        libboost-filesystem-dev libboost-program-options-dev
}

check_versions() {
    info "Checking version requirements..."
    # Python
    if command_exists python3; then
        local v; v=$(python3 --version 2>&1 | awk '{print $2}')
        local major minor; major=${v%%.*}; minor=${v#*.}; minor=${minor%%.*}
        (( major > 3 || (major == 3 && minor >= 8) )) \
            && ack "Python version $v is sufficient (>= 3.8)" \
            || warn "Python version $v might be too old (recommended >= 3.8)"
    else
        warn "Python3 is not installed"
    fi
    # GCC
    if command_exists gcc; then
        local v; v=$(gcc -dumpversion | cut -d. -f1,2)
        awk "BEGIN{exit !($v >= 8.0)}" && ack "GCC version $v is sufficient (>= 8.0)" \
            || warn "GCC version $v might be too old (recommended >= 8.0)"
    else
        warn "GCC is not installed"
    fi
    # Make
    if command_exists make; then
        local v; v=$(make --version | head -n1 | awk '{print $3}' | cut -d'.' -f1,2)
        ack "Make version $v available"
    else
        warn "Make is not installed"
    fi
    # CMake
    if command_exists cmake; then
        local v; v=$(cmake --version | head -n1 | awk '{print $3}' | cut -d'.' -f1,2)
        awk "BEGIN{exit !($v >= 3.10)}" && ack "CMake version $v is sufficient (>= 3.10)" \
            || warn "CMake version $v might be too old (recommended >= 3.10)"
    else
        warn "CMake is not installed"
    fi
}

setup_env() {
    info "Configuring environment variables..."
    local bashrc="$HOME/.bashrc"
    local env_vars=(
        'export PATH=$HOME/.local/bin:$PATH'
        'export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH'
        'export PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig:$PKG_CONFIG_PATH'
    )
    for var in "${env_vars[@]}"; do
        grep -Fxq "$var" "$bashrc" 2>/dev/null || echo "$var" >> "$bashrc"
    done
    ack "Environment variables configured"
}

main() {
    info "Starting BCF project dependency installation..."
    detect_os
    info "Detected OS: $OS $VER"
    [[ $EUID -eq 0 ]] && fatal "Do not run as root. Use a regular user with sudo privileges."
    sudo -n true 2>/dev/null || warn "Sudo privileges required. You may be prompted."
    install_kernel_deps
    install_solver_deps
    install_vm_deps
    install_python_deps
    install_prevail_deps
    setup_env
    check_versions
    ack "Dependency installation completed successfully!"
    info "You can now build BCF project components:"
    info "  - ./scripts/build.sh solver"
    info "  - ./scripts/build.sh kernel"
    info "  - ./scripts/build.sh all"
}

show_help() {
    cat <<EOF
BCF Project Dependency Installer

Usage: $0 [OPTIONS]

Options:
  -h, --help     Show this help message
  --check-only   Only check what dependencies are missing (don't install)

This script installs all system dependencies required for the BCF project:
  - Kernel building tools and headers
  - CVC5 solver build dependencies
  - VM and virtualization tools (QEMU, virtiofsd)
  - Python packages for analysis scripts

Supports multiple Linux distributions and package managers.
EOF
}

CHECK_ONLY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) show_help; exit 0 ;;
        --check-only) CHECK_ONLY=true; shift ;;
        *) echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

if $CHECK_ONLY; then
    info "Running in check-only mode..."
    detect_os
    info "Detected OS: $OS $VER"
    check_versions
    info "Check completed. Run without --check-only to install missing dependencies."
else
    main "$@"
fi
