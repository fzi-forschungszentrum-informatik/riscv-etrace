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
