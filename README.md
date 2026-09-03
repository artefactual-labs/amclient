# amclient

[![GitHub CI](https://github.com/artefactual-labs/amclient/actions/workflows/test.yml/badge.svg)](https://github.com/artefactual-labs/amclient/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/artefactual-labs/amclient/branch/main/graph/badge.svg?token=hJLGYzoJUo)](https://codecov.io/gh/artefactual-labs/amclient)

AMClient is an Archivematica API client library and Python package for making
it easier to talk to Archivematica from your Python scripts. AMClient also acts
as a command line application which can easily be combined with shell-scripts
to perform the same functions as a Python script might.

AMClient brings together the majority of the functionality of the two primary
Archivematica components:

* [Archivematica API][archivematica-api]
* [Storage Service API][storage-service-api]

Basic usage:

```shell
amclient.py <subcommand> [optional arguments] <positional argument(s)>
```

E.g.:

```shell
amclient.py close-completed-transfers \
    --am-user-name test 234deffdf89d887a7023546e6bc0031167cedf6
```

To see a list of all commands and how they are used, then run `amclient.py`
without any arguments.

To understand how to use an individual subcommand, simply run:
`amclient.py <subcommand>`, the output will describe the input parameters for
that command:

E.g.:

```shell
usage: amclient extract-file [-h] [--ss-user-name USERNAME] [--ss-url URL]
                              [--directory DIR]
                              [--saveas-filename SAVEASFILENAME]
                              ss_api_key package_uuid relative_path
```

Calling the module from Python:

E.g.:

```python
from amclient import AMClient

am = AMClient()
am.ss_url = "http://127.0.0.1:62081"
am.ss_user_name = "test"
am.ss_api_key = "test"
am.list_storage_locations()
# ...json is output here...
```

## Idempotent transfer submission

Archivematica can safely replay transfer submissions when the client supplies
an idempotency key. The caller must choose a stable key and reuse it with the
same transfer parameters for every retry:

```python
from amclient import AMClient

am = AMClient(
    am_url="http://127.0.0.1:62080",
    am_user_name="test",
    am_api_key="test",
    transfer_directory="/path/to/transfer",
    transfer_name="example-transfer",
    transfer_type="standard",
    processing_config="automated",
    idempotency_key="workflow-123-transfer",
)
result = am.create_package()
```

The option is also available to the command-line client:

```shell
amclient create-package API_KEY /path/to/transfer \
    --idempotency-key workflow-123-transfer
```

Archivematica accepts keys containing 1-255 visible ASCII characters without
whitespace. It returns HTTP 409 while an identical request is still in progress
and HTTP 422 when the key is reused with different transfer parameters. Python
callers can set `enhanced_errors=True` to inspect these responses through the
returned error object's `status_code` and `message` attributes.

## Python API status

> [!NOTE]
> `amclient` exposes a first-generation Python API that grew alongside the
> Archivematica and Storage Service APIs. Its dynamic attribute-based
> configuration, largely untyped return values, and legacy integer-based error
> handling should not be considered the intended design for a future major
> version.
>
> We welcome discussion and contributions toward a typed v2 client with explicit
> operation inputs, consistent response and exception models, and a clearer
> separation between library and CLI concerns. The [Archivematica API
> specification] may also enable parts of the client's development to be
> automated while keeping its implementation aligned with the API contract.

## CONTRIBUTING

For information about contributing to this project please see the AMClient
[CONTRIBUTING.md][contributing]

[archivematica-api]: https://wiki.archivematica.org/Archivematica_API
[storage-service-api]: https://wiki.archivematica.org/Storage_Service_API
[contributing]: CONTRIBUTING.md
[archivematica api specification]: https://github.com/archivematica/archivematica-api-specification
