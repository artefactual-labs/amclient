[![Travis CI](https://travis-ci.org/artefactual-labs/amclient.svg?branch=master)](https://travis-ci.org/artefactual-labs/amclient)

# amclient

The transfers/amclient.py script is a module and CLI that provides
functionality for interacting with the various Archivematica APIs.

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
