# Development notes

When contributing, please make sure to follow these rules:
 * Every commit should compile on its own and all unit tests should pass.
 * The examples should also compile for every commit.
 * Keep clippy happy.
 * Keep rustfmt happy.
 * Make sure all references inside the documentation are valid (at least when
   all features are active).
 * Warnings about unused items are explicitly allowed if those items are used in
   the near future.
 * Comments should be restricted to the first 80 characters of a line.
 * Do not depend on public re-exports from other modules (of the crate). Import
   items directly.

## Testing

Unit tests are run via `cargo test`. There are currently no integration tests,
i.e. the toplevel `tests` directory does not exist.

Aside from that, end-to-end tests may be performed using the `simple` example.
The following describes how to test against the reference flow from the
specification repository https://github.com/riscv-non-isa/riscv-trace-spec/.

We assume that the repository is already cloned and the instructions for
instruction trace testing in `referenceFlow/README` were followed. Those result
in the presence of a regression directory, e.g. `regression_20250425_190845`
containing a directory `spike` and one or more test suite specific directories
such as `itype3_basic`. Some commands below will assume that those directories'
paths are held in the shell variables `${spike}` and `${suite}`.

The suite directory contains "static" encoder/decoder configuration in an INI
format. That configuration needs to be converted into a TOML format understood
by the "simple" example. This can be done by simply stripping some elements:

```sh
egrep -v '^[#[]' "${suite}/hardware_32.scf" > params_32.toml
```

The programs used for tests reside in `referenceFlow/tests/test_files`. Each
file with the extension `.riscv` or `.pk` are ELF files and correspond to one
test. As this library currently only supports RV32I, we need to determine
whether an ELF file is 32bit or 64bit, e.g. using the `file` utility.

Having selected an ELF file `${elf}`, we can determine the raw trace file and
reference spike trace from the ELF's basename. The "simple" example can then
perform tracing and compare its trace against the reference:

```sh
test_name=`basename -s.riscv ${elf}`
trace_file=${suite}/${test_name}.te_inst_raw
spike_trace=${spike}/${test_name}.spike_pc_trace
cargo run --example simple --all-features -- "${elf}" "${trace_file}" params_32.toml "${spike_trace}"
```

If a missmatch is found or an error occurred while tracing, the example
will abort.
