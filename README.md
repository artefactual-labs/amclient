[![Travis CI](https://travis-ci.org/artefactual-labs/amclient.svg?branch=master)](https://travis-ci.org/artefactual-labs/amclient)

# amclient

AMClient is an Archivematica API client library and Python package for making
it easier to talk to Archivematica from your Python scripts. AMClient also acts
as a command line application which can easily be combined with shell-scripts
to perform the same functions as a Python script might.

AMClient brings together the majority of the functionality of the two primary
Archivematica components:

* [Archivematica API][archivematica-api]
* [Storage Service API][storage-service-api]

Basic usage:
    `amclient.py <subcommand> [optional arguments] <positional argument(s)>`

  E.g.:
  ```bash
    amclient.py close-completed-transfers \
        --am-user-name test 234deffdf89d887a7023546e6bc0031167cedf6
  ```

To see a list of all commands and how they are used, then run `amclient.py`
without any arguments.

To understand how to use an individual subcommand, simply run:
`amclient.py <subcommand>`, the output will describe the input parameters for
that command:

  E.g.:
  ```bash
    usage: amclient extract-file [-h] [--ss-user-name USERNAME] [--ss-url URL]
                                 [--directory DIR]
                                 [--saveas-filename SAVEASFILENAME]
                                 ss_api_key package_uuid relative_path
  ```

Calling the module from Python:

  E.g.:
```python
    Python 3.6.7 (default, Oct 22 2018, 11:32:17)
    [GCC 8.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from amclient import AMClient
    >>> am = AMClient()
    >>> am.ss_url = "http://127.0.0.1:62081"
    >>> am.ss_user_name = "test"
    >>> am.ss_api_key = "test"
    >>> am.list_storage_locations()
    ...json is output here...
```

## CONTRIBUTING

For information about contributing to this project please see the AMClient
[CONTRIBUTING.md][contributing]

[archivematica-api]: https://wiki.archivematica.org/Archivematica_API
[storage-service-api]: https://wiki.archivematica.org/Storage_Service_API
[contributing]: CONTRIBUTING.md
