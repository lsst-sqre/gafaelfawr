# Kubernetes operator test data

The files in this directory are used in tests for Kubernetes operators.

The `input` subdirectory contains custom resources that the operator is expected to act on.
The `output` subdirectory contains the results.
File names should match between the directories: a file in `input` should create the resources contained in the corresponding file in `output`.

There may be files in `input` with no corresponding file in `output` to test error cases.

All files are in templated YAML.
Templating is done through the regular Python `format` syntax.
The following variables will be expanded before the files are used:

`braces`
    Expands to `{}`.
    The same as putting `{{}}` in the input, except that triggers a YAML error.

`namespace`
    The namespace used by the test.
    These namespaces have random names and are created by a fixture before each Kubernetes operator test.

The following variables are expanded only in output files:

`any`
    Becomes `unittest.mock.ANY`.

Both the `input` and `output` files may contain multiple resources using the normal YAML `---` document separator.
