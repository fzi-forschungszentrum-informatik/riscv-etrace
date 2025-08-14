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
such as `itype3_basic`. Some commands below will assume that the latter
directory's path is held in the shell variable `${suite}`.

The `simple` example can be executed in reference checking mode for all tests
in a suite for which a trace exists by running a test-script from the project's
root directory:

``sh
doc/test-reference.sh ${suite}
``
