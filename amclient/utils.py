# -*- coding: utf-8 -*-

"""Where you put stuff when you can't think of a good name for a module."""

import logging
import sys

import requests
import urllib3
from six import binary_type, text_type

try:
    import errors
except ImportError:
    from amclient import errors


LOGGER = logging.getLogger("amclient")

METHOD_GET = "GET"
METHOD_POST = "POST"
METHOD_DELETE = "DELETE"


class Error(int):
    """Subclass of int which accepts additional attributes. This allows specific
    error messages to be passed through requests"""

    def __new__(cls, *args, **kwargs):
        i = int.__new__(cls, *args)
        i.message = kwargs.get("message")
        return i

    @classmethod
    def from_request_exception(cls, error_code, request_exception):
        response = request_exception.response
        if response is None:
            return Error(error_code)
        try:
            message = response.json()
        except requests.exceptions.JSONDecodeError:
            message = response.text
        return Error(error_code, message=message)


def _call_url(
    url, params=None, method=METHOD_GET, headers=None, data=None, assume_json=True
):
    """Helper to GET a URL.

    :param str url: URL to call
    :param dict params: Params to pass as HTTP query string
    :param str method: HTTP method (e.g., 'GET')
    :param dict headers: HTTP headers
    :param dict data: Data to pass to request body
    :param bool assume_json: set to False if the response body should not be
                             decoded as JSON
    :returns: Dict of the returned JSON or raises an exception
    """
    response = requests.request(
        method, url=url, params=params, headers=headers, data=data
    )
    LOGGER.debug("Response: %s", response)
    LOGGER.debug("type(response.text): %s ", type(response.text))
    LOGGER.debug("Response content-type: %s", response.headers["content-type"])
    response.raise_for_status()
    if assume_json:
        return response.json()
    return response.text


def _call_url_json(
    url,
    params=None,
    method=METHOD_GET,
    headers=None,
    assume_json=True,
    enhanced_errors=False,
):
    """Helper to GET a URL where the expected response is 200 with JSON.

    :param str url: URL to call
    :param dict params: Params to pass as HTTP query string or JSON body
    :param str method: HTTP method (e.g., 'GET')
    :param dict headers: HTTP headers
    :param bool assume_json: set to False if the response body should not be
                             decoded as JSON
    :returns: Dict of the returned JSON or an integer error
            code to be looked up
    """
    method = method.upper()
    LOGGER.debug("URL: %s; params: %s; method: %s", url, params, method)
    try:
        if method == METHOD_GET or method == METHOD_DELETE:
            data = _call_url(
                url,
                method=method,
                params=params,
                headers=headers,
                assume_json=assume_json,
            )
        else:
            data = _call_url(
                url,
                method=method,
                data=params,
                headers=headers,
                assume_json=assume_json,
            )
    except (
        urllib3.exceptions.NewConnectionError,
        requests.exceptions.ConnectionError,
    ) as err:
        LOGGER.error("Connection error %s", err)
        return errors.ERR_SERVER_CONN
    except requests.exceptions.RequestException as err:
        LOGGER.debug("Response: %s", err.response.text)
        LOGGER.warning(
            "%s Request to %s returned %s %s",
            method,
            url,
            err.response.status_code,
            err.response.reason,
        )
        return (
            Error.from_request_exception(errors.ERR_INVALID_RESPONSE, err)
            if enhanced_errors
            else errors.ERR_INVALID_RESPONSE
        )
    except ValueError as err:
        LOGGER.warning("Could not parse JSON from response: %s", str(err))
        return errors.ERR_PARSE_JSON
    return data


try:
    from os import fsencode, fsdecode
except ImportError:
    # Cribbed & modified from Python3's OS module to support Python2
    def fsencode(filename):
        """Encode path-like filename to the filesystem encoding.

        See https://docs.python.org/3/library/os.html#os.fsencode for more
        details.
        """
        encoding = sys.getfilesystemencoding()
        if isinstance(filename, binary_type):
            return filename
        elif isinstance(filename, text_type):
            return filename.encode(encoding)
        else:
            raise TypeError("expect bytes or str, not %s" % type(filename).__name__)

    def fsdecode(filename):
        """Decode the path-like filename from the filesystem encoding.

        See https://docs.python.org/3/library/os.html#os.fsdecode for more
        details.
        """
        encoding = sys.getfilesystemencoding()
        if isinstance(filename, text_type):
            return filename
        elif isinstance(filename, binary_type):
            return filename.decode(encoding)
        else:
            raise TypeError("expect bytes or str, not %s" % type(filename).__name__)
