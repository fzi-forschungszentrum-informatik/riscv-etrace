#!/bin/sh
#
# This script runs the simple example in testing mode against reference flow
# tests.
#
# Usage:
#
#       test-reference.sh <test suite dir>
#
# Where `test suite dir` is the suite directory produced when running the
# reference flow's `run_regression.sh` script, e.g. `itype3_basic` in a
# directory `regression_20250624_124010`.
#
# This script will produce the parameter files `params_32.toml` and
# `params_64.toml` in the current working directory and run the simple
# example for all test files for which a trace file is present.

die() {
    echo "$1" >&2
    exit 1
}

suite=$1
spike="${suite}/../spike"

if [ ! -d "${suite}" ]; then
    die "Suite directory '${suite}' does not exist"
fi
if [ ! -d "${spike}" ]; then
    die "Spike directory '${spike}' does not exist"
fi

echo "Extracting parameters..."
if [ -e "${suite}/hardware_32.scf" ]; then
    egrep -v '^[#[]' "${suite}/hardware_32.scf" > params_32.toml
else
    die "32bit Parameter file does not exist"
fi
if [ -e "${suite}/hardware_64.scf" ]; then
    egrep -v '^[#[]' "${suite}/hardware_64.scf" > params_64.toml
else
    die "64bit Parameter file does not exist"
fi

test_files_dir="${suite}/../../tests/test_files/"
for elf in "${test_files_dir}"*.riscv "${test_files_dir}"*.pk; do
    if file ${elf} | grep -q 'ELF 64-bit'; then
        params="params_64.toml"
    elif file ${elf} | grep -q 'ELF 32-bit'; then
        params="params_32.toml"
    else
        echo "Ignoring ${test_name}: unknown ELF type"
        continue;
    fi
    test_name=`basename -s.riscv ${elf}`
    test_name=`basename -s.pk ${test_name}`
    spike_trace=${spike}/${test_name}.spike_pc_trace
    trace_file=${suite}/${test_name}.te_inst_raw
    if [ ! -e "$trace_file" ]; then
        echo "Ignoring ${test_name}: no trace file present"
        continue;
    fi
    echo "Checking with ${test_name}..."
    cargo run --example simple --all-features -- "${elf}" "${trace_file}" "${params}" "${spike_trace}" >> /dev/null
done
