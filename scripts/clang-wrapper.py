#!/usr/bin/env python3
import json
import os
import sys

# Configuration file that defines which compiler, version, and optimization level to use
COMPILER_CONFIG_FILE = "/path/to/compiler_config.json"


def load_config():
    """Load the compiler configuration from the configuration file, which follows:
        {
            "compiler": "gcc-11",
            "optimization": "-O3"
        }
    """
    if not os.path.exists(COMPILER_CONFIG_FILE):
        print(
            f"Configuration file {COMPILER_CONFIG_FILE} not found", file=sys.stderr)
        sys.exit(1)

    try:
        with open(COMPILER_CONFIG_FILE, "r") as f:
            config = json.load(f)
    except Exception as e:
        print(f"Failed to read configuration file: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate configuration content
    required_keys = {"compiler", "optimization"}
    if not all(key in config for key in required_keys):
        print(
            f"Invalid configuration: missing keys. Required: {required_keys}", file=sys.stderr)
        sys.exit(1)

    return config


def adjust_args(args, optimization_level):
    """
    Adjust the arguments to replace any existing optimization flag with the desired one.
    If no optimization flag is present, add it.
    """
    adjusted_args = []
    replaced = False

    for arg in args:
        if arg.startswith("-O") and len(arg) > 2:
            adjusted_args.append(optimization_level)
            replaced = True
        else:
            adjusted_args.append(arg)

    if not replaced:
        adjusted_args.append(optimization_level)

    return adjusted_args


def main():
    # Load configuration
    config = load_config()
    compiler = config["compiler"]
    optimization_level = config["optimization"]

    # Adjust arguments
    original_args = sys.argv[1:]  # Exclude the script name
    adjusted_args = adjust_args(original_args, optimization_level)

    # Find the compiler executable under /usr/bin or /usr/local/bin
    binary = None
    for path in ["/usr/bin", "/usr/local/bin"]:
        if os.path.exists(f"{path}/{compiler}"):
            binary = f"{path}/{compiler}"
            break

    if binary is None:
        print(f"Compiler {compiler} not found", file=sys.stderr)
        sys.exit(1)

    # Execute the compiler with adjusted arguments
    # print([binary] + adjusted_args)
    try:
        import subprocess

        result = subprocess.run(
            [binary] + adjusted_args, check=False, env=os.environ)
        sys.exit(result.returncode)
    except Exception as e:
        print(f"Failed to invoke the compiler: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
