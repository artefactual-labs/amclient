#!/usr/bin/env python
"""Archivematica Client.

Module and CLI that holds functionality for interacting with the various
Archivematica APIs.
"""

import base64
import binascii
import io
import json
import logging
import os
import pprint
import re
import sys
from collections import defaultdict

import requests

from . import amclientargs
from . import defaults
from . import errors
from . import loggingconfig
from . import utils
from . import version

LOGGER = logging.getLogger("amclient")


def b64decode_ts_location_browse(result):
    """Base64-decode the results of a call to SS GET
    /location/UUID/browse/.
    """

    def dec(thing):
        try:
            thing = base64.b64decode(thing.encode("utf8"))
        except UnicodeEncodeError:
            LOGGER.warning(
                "Failed to UTF8-encode output from GET call to SS"
                " /location/UUID/browse/: %s",
                result,
            )
        except (binascii.Error, TypeError):
            LOGGER.warning(
                "Failed to base64-decode file or directory names in"
                " output from GET call to SS"
                " /location/UUID/browse/: %s",
                result,
            )
        try:
            return thing.decode("utf8")
        except ValueError:
            LOGGER.debug(
                "Unable to decode a transfer source component using"
                " the UTF-8 codec; trying to guess the encoding..."
            )
            try:
                import chardet
            except ImportError:
                LOGGER.debug(defaults.UNDEC_MSG)
                return defaults.UNDECODABLE
            encoding = chardet.detect(thing).get("encoding")
            if encoding:
                try:
                    return thing.decode(encoding)
                except ValueError:
                    LOGGER.debug(defaults.UNDEC_MSG)
                    return defaults.UNDECODABLE
            LOGGER.debug(defaults.UNDEC_MSG)
            return defaults.UNDECODABLE

    try:
        result["directories"] = [dec(d) for d in result["directories"]]
        result["entries"] = [dec(e) for e in result["entries"]]
        result["properties"] = {
            dec(key): val for key, val in result["properties"].items()
        }
    except ValueError as error:
        LOGGER.warning(
            "GET call to SS /location/UUID/browse/ returned an"
            " unrecognized data structure: %s",
            result,
        )
        LOGGER.warning(error)
    return result


def is_uuid(thing):
    return defaults.UUID_PATT.search(thing) is not None


class AMClient:
    reingest_type = "FULL"
    transfer_type = "standard"

    def __init__(self, **kwargs):
        """Construct an Archivematica client. Provide any of the following
        arguments, depending on what you want the client to do.
        param: ss_url
        param: ss_user_name
        param: ss_api_key
        param: am_url
        param: am_user_name
        param: am_api_key
        param: output_mode
        param: transfer_source
        param: transfer_path
        param: sip_uuid
        param: aip_uuid
        param: dip_uuid
        param: directory
        param: stream
        param: cli_call
        param: enhanced_errors
        param: event_reason
        param: pipeline_uuid
        param: location_uuid
        param: pipeline_uuids
        param: ss_user_id
        param: ss_user_email
        """
        for key, val in kwargs.items():
            setattr(self, key, val)

    # stdout and __getattr__ help us to deal with class output, and output
    # formatting in a useful way, e.g. returning user friendly error messages
    # from any failed calls to the AM or SS servers.
    def stdout(self, stuff):
        """Print to stdout, either as JSON or pretty-printed Python."""
        if self.output_mode.lower() == "json":
            print(json.dumps(stuff))
        else:
            pprint.pprint(stuff)

    def __getattr__(self, name):
        if name.startswith("print_"):
            try:
                method = name.replace("print_", "", 1)
                res = getattr(self, method)()
                # Shortening variable for PEP8 conformance.
                err_lookup = errors.error_lookup
                if isinstance(res, int):
                    self.stdout(
                        err_lookup.get(res, err_lookup(errors.ERR_CLIENT_UNKNOWN))
                    )
                else:
                    # Output to stdout if the returning function hasn't
                    # returned None (or an error). To enable functions
                    # returning None to manage their own output streams.
                    if res:
                        self.stdout(res)
            except requests.exceptions.InvalidURL:
                self.stdout(errors.error_lookup(errors.ERR_INVALID_URL))
            except Exception:
                self.stdout(errors.error_lookup(errors.ERR_CLIENT_UNKNOWN))
        else:
            raise AttributeError(f"AMClient has no method {name}")

    @staticmethod
    def version():
        """Return the module version."""
        return version.version()

    def _am_auth(self):
        """Create JSON parameters for authentication in the request body to
        the Archivematica API.
        """
        return {"username": self.am_user_name, "api_key": self.am_api_key}

    def _ss_auth(self):
        """Create JSON parameters for authentication in the request body to
        the Storage Service API.
        """
        return {"username": self.ss_user_name, "api_key": self.ss_api_key}

    def _am_auth_headers(self):
        """Generate a HTTP request header for the Archivematica API."""
        return {"Authorization": f"ApiKey {self.am_user_name}:{self.am_api_key}"}

    def _ss_auth_headers(self):
        """Generate a HTTP request header for Storage Service API."""
        return {"Authorization": f"ApiKey {self.ss_user_name}:{self.ss_api_key}"}

    def hide_unit(self, unit_uuid, unit_type):
        """GET <unit_type>/<unit_uuid>/delete/."""
        return utils._call_url_json(
            f"{self.am_url}/api/{unit_type}/{unit_uuid}/delete/",
            params=self._am_auth(),
            method=utils.METHOD_DELETE,
        )

    def close_completed_transfers(self):
        """Close all completed transfers::

            $ ./amclient.py close-completed-transfers \
                --am-user-name=test \
                e8f8a0fb157f08a260045f805455e144d8ad0a5b
        """
        return self._close_completed_units("transfer")

    def close_completed_ingests(self):
        """Close all completed ingests::

            $ ./amclient.py close-completed-ingests \
                --am-user-name=test \
                e8f8a0fb157f08a260045f805455e144d8ad0a5b
        """
        return self._close_completed_units("ingest")

    def _close_completed_units(self, unit_type):
        """Close all completed transfers/ingests."""
        try:
            _completed_units = getattr(self, f"completed_{unit_type}s")().get("results")
        except AttributeError:
            _completed_units = None
        ret = defaultdict(list)
        if _completed_units is None:
            msg = (
                "Something went wrong when attempting to retrieve the"
                f" completed {unit_type}s."
            )
            LOGGER.warning(msg)
        else:
            for unit_uuid in _completed_units:
                ret[f"completed_{unit_type}s"].append(unit_uuid)
                response = self.hide_unit(unit_uuid, unit_type)
                if isinstance(response, int):
                    ret["close_failed"].append(unit_uuid)
                    LOGGER.warning("FAILED to close %s %s.", unit_type, unit_uuid)
                else:
                    ret["close_succeeded"].append(unit_uuid)
                    LOGGER.info("Closed %s %s.", unit_type, unit_uuid)
        return ret

    def completed_transfers(self):
        """Return all completed transfers. GET /transfer/completed::

            $ ./amclient.py completed-transfers \
                --am-user-name=test \
                e8f8a0fb157f08a260045f805455e144d8ad0a5b
        """
        return utils._call_url_json(
            f"{self.am_url}/api/transfer/completed", self._am_auth()
        )

    def completed_ingests(self):
        """Return all completed ingests. GET /ingest/completed::

            $ ./amclient.py completed-ingests \
                --am-user-name=test \
                e8f8a0fb157f08a260045f805455e144d8ad0a5b
        """
        return utils._call_url_json(
            f"{self.am_url}/api/ingest/completed", self._am_auth()
        )

    def unapproved_transfers(self):
        """Return all unapproved transfers. GET transfer/unapproved::

            $ ./amclient.py unapproved-transfers \
                --am-user-name=test \
                --am-api-key=e8f8a0fb157f08a260045f805455e144d8ad0a5b
        """
        return utils._call_url_json(
            f"{self.am_url}/api/transfer/unapproved", self._am_auth()
        )

    def transferables(self, b64decode=True):
        """Return all transferable entities in the Storage Service.

        GET location/<TS_LOC_UUID>/browse/::

            $ ./amclient.py transferables \
                --ss-user-name=test \
                --ss-api-key=7558e7485cf8f20aadbd95f6add8b429ba11cd2b \
                --transfer-source=7ea1eb0e-5f4e-42e0-836d-c9b4ab5692e1 \
                --transfer-path=vagrant/archivematica-sampledata
        """
        url = f"{self.ss_url}/api/v2/location/{self.transfer_source}/browse/"
        params = self._ss_auth()
        if self.transfer_path:
            params["path"] = base64.b64encode(os.fsencode(self.transfer_path))
        result = utils._call_url_json(url, params)
        if b64decode:
            return b64decode_ts_location_browse(result)
        return result

    def get_package(self, params=None):
        """SS GET /api/v2/file/?<GET_PARAMS>."""
        payload = self._ss_auth()
        payload.update(params)
        return utils._call_url_json(f"{self.ss_url}/api/v2/file/", payload)

    def get_package_details(self):
        """SS GET /api/v2/file/<uuid>. Retrieve the details of a specific
        package given a package uuid.
        """
        return utils._call_url_json(
            f"{self.ss_url}/api/v2/file/{self.package_uuid}",
            headers=self._ss_auth_headers(),
        )

    def get_next_package_page(self, next_path):
        """SS GET  /api/v2/file/?<GET_PARAMS> using the next URL from
        previous responses, which includes the auth. parameters.
        """
        return utils._call_url_json(f"{self.ss_url}{next_path}", {})

    def aips(self, params=None):
        """Retrieve the details of a specific AIP."""
        final_params = {"package_type": "AIP"}
        if params:
            final_params.update(params)
        return self.get_all_packages(final_params)

    def dips(self, params=None):
        """Retrieve the details of a specific DIP."""
        final_params = {"package_type": "DIP"}
        if params:
            final_params.update(params)
        return self.get_all_packages(final_params)

    def get_all_packages(self, params=None, packages=None, next_=None):
        """Get all packages (AIPs or DIPs) in the Storage Service, following
        the pagination trail if necessary.
        """
        if not packages:
            packages = []
        if next_:
            response = self.get_next_package_page(next_)
        else:
            response = self.get_package(params)
        if not response:
            raise Exception("Error connecting to the SS")
        packages = packages + response["objects"]
        if response["meta"]["next"]:
            packages = self.get_all_packages(params, packages, response["meta"]["next"])
        return packages

    def get_all_compressed_aips(self):
        """Retrieve a dict of compressed AIPs in the Storage Service.

        The dict is indexed by the AIP UUIDs. To retrieve a list of UUIDs only,
        access the dict using aips.keys(). To access the aip metadata, call
        aips.values().
        """
        compressed_aips = {}
        for aip in self.aips():
            if aip["status"] == "UPLOADED":
                path = aip["current_full_path"]
                compressed = self.find_compressed(path)
                if compressed:
                    compressed_aips[aip["uuid"]] = aip
        return compressed_aips

    def find_compressed(self, path):
        """A .7z file extension might indicate if a file is compressed. We try
        to identify that here.
        """
        compressed_file_ext = [".7z"]
        uncompressed_file_ext = ""
        file_name, file_extension = os.path.splitext(path)
        LOGGER.debug("Found filename %s with extension %s", file_name, file_extension)
        file_extension = file_extension.strip()
        if file_extension in compressed_file_ext:
            return True
        elif file_extension == uncompressed_file_ext:
            return False
        LOGGER.warning("Status of AIP compression is unconfirmed")
        return None

    def aip2dips(self):
        """Get all DIPS created from AIP with UUID ``self.aip_uuid``.

        Note: although desirable, it appears that this cannot be accomplished
        by only getting DIPs that are related to the target AIP using
        tastypie's filters. That is, the current SS API does not allow a filter
        like 'current_path__endswith': self.aip_uuid nor does the
        related_packages m2m resource attribute appear to be useful in this
        area. Please inform if this is inaccurate.
        """
        _dips = self.dips()
        return [d for d in _dips if d["current_path"].endswith(self.aip_uuid)]

    def aips2dips(self):
        """Get all AIP UUIDs and map them to their DIP UUIDs, if any."""
        _dips = self.dips()
        return {
            a["uuid"]: [
                d["uuid"] for d in _dips if d["current_path"].endswith(a["uuid"])
            ]
            for a in self.aips()
        }

    def download_package(self, uuid):
        """Download the package from SS by UUID."""
        url = f"{self.ss_url}/api/v2/file/{uuid}/download/"
        response = requests.get(url, params=self._ss_auth(), stream=True)
        if response.status_code == 200:
            try:
                local_filename = re.findall(
                    'filename="(.+)"', response.headers["content-disposition"]
                )[0]
            except KeyError:
                # NOTE: assuming that packages are always stored as .7z
                local_filename = f"package-{uuid}.7z"
            if getattr(self, "directory", None):
                dir_ = self.directory
                if os.path.isdir(dir_):
                    local_filename = os.path.join(dir_, local_filename)
                else:
                    LOGGER.warning(
                        "There is no directory %s; saving %s to %s instead",
                        dir_,
                        local_filename,
                        os.getcwd(),
                    )
            with open(local_filename, "wb") as file_:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file_.write(chunk)
            return local_filename
        else:
            LOGGER.warning("Unable to download package %s", uuid)

    def get_pipeline_details(self):
        """SS GET /api/v2/pipeline/<uuid>. Retrieve the details of a specific
        pipeline given a pipeline uuid.
        """
        return utils._call_url_json(
            f"{self.ss_url}/api/v2/pipeline/{self.pipeline_uuid}",
            headers=self._ss_auth_headers(),
        )

    def get_pipelines(self):
        """GET Archivematica Pipelines (dashboard instances from the storage
        service.
        """
        return utils._call_url_json(
            f"{self.ss_url}/api/v2/pipeline/", headers=self._ss_auth_headers()
        )

    def get_transfer_status(self):
        """Given a Transfer UUID, GET the transfer status.

        If there isn't a transfer with this UUID in the pipeline then the
        response from the server will look as follows::

            {"message": "Cannot fetch unitTransfer with UUID"
                        " ebc8a35c-6742-4264-bc30-22e263966d69",
             "type": "transfer",
             "error": true}
        The response suggesting non-existence is an error, "error": true, is
        something the caller will have to handle appropriately for their
        application.
        """
        return utils._call_url_json(
            f"{self.am_url}/api/transfer/status/{self.transfer_uuid}/",
            headers=self._am_auth_headers(),
        )

    def get_ingest_status(self):
        """GET ingest status if there is an ingest in progress in the
        Archivematica pipeline.
        """
        return utils._call_url_json(
            f"{self.am_url}/api/ingest/status/{self.sip_uuid}/",
            headers=self._am_auth_headers(),
        )

    def get_unit_status(self, uuid):
        """Look up the status of an ingest or transfer unit using the transfer
        UUID."""
        transfer = utils._call_url(
            f"{self.am_url}/api/transfer/status/{uuid}",
            headers=self._am_auth_headers(),
        )
        if (
            transfer.get("status") == "COMPLETE"
            and transfer.get("sip_uuid")
            and transfer.get("sip_uuid") != "BACKLOG"
        ):
            sip_uuid = transfer.get("sip_uuid")
            if not sip_uuid:
                return transfer

            return utils._call_url(
                f"{self.am_url}/api/ingest/status/{sip_uuid}",
                headers=self._am_auth_headers(),
            )
        return transfer

    def get_processing_config(self, assume_json=False):
        """GET a processing configuration file from an Archivematica instance.

        if the request is successful an application/xml response is returned
        to the caller. If the request is unsuccessful then an error code is
        returned which needs to be handled via error_lookup. The default is to
        return the default processing config from the AM server.
        """
        return utils._call_url_json(
            f"{self.am_url}/api/processing-configuration/{self.processing_config}",
            headers=self._am_auth_headers(),
            assume_json=assume_json,
        )

    def approve_transfer(self):
        """Approve a transfer in the Archivematica Pipeline.

        The transfer_type informs Archivematica how to continue processing.
        Options are:
          * standard
          * unzipped bag
          * zipped bag
          * dspace
        Directory is the location where the transfer is to be picked up
        from. The directory can be found via the get_transfer_status API
        call.
        """
        url = f"{self.am_url}/api/transfer/approve/"
        params = {
            "type": self.transfer_type,
            "directory": os.fsencode(self.transfer_directory),
        }
        return utils._call_url_json(
            url,
            headers=self._am_auth_headers(),
            params=params,
            method=utils.METHOD_POST,
        )

    def approve_partial_reingest(self):
        """Approve a partial reingest using the SIP UUID."""
        url = f"{self.am_url}/api/ingest/reingest/approve/"
        params = {"uuid": self.sip_uuid}
        return utils._call_url_json(
            url,
            headers=self._am_auth_headers(),
            params=params,
            method=utils.METHOD_POST,
        )

    def reingest_aip(self):
        """Initiate the reingest of an AIP via the Storage Service given the
        API UUID and Archivematica Pipeline.

        Reingest default is set to
        ``full``. Alternatives are:
            * METADATA_ONLY (metadata only re-ingest)
            * OBJECTS (partial re-ingest)
            * FULL (full re-ingest)
        """
        params = {
            "pipeline": self.pipeline_uuid,
            "reingest_type": self.reingest_type,
            "processing_config": self.processing_config,
        }
        url = f"{self.ss_url}/api/v2/file/{self.aip_uuid}/reingest/"
        return utils._call_url_json(
            url,
            headers=self._ss_auth_headers(),
            params=json.dumps(params),
            method=utils.METHOD_POST,
        )

    def download_dip(self):
        return self.download_package(self.dip_uuid)

    def download_aip(self):
        return self.download_package(self.aip_uuid)

    def delete_package(
        self, package_uuid, pipeline_uuid, event_reason, ss_user_id, ss_user_email
    ):
        """Create a deletion request for a package."""
        params = {
            "pipeline": pipeline_uuid,
            "event_reason": event_reason,
            "user_id": ss_user_id,
            "user_email": ss_user_email,
        }
        url = f"{self.ss_url}/api/v2/file/{package_uuid}/delete_aip/"
        return utils._call_url_json(
            url,
            headers=self._ss_auth_headers(),
            params=json.dumps(params),
            method=utils.METHOD_POST,
        )

    def delete_aip(self):
        return self.delete_package(
            self.aip_uuid,
            self.pipeline_uuid,
            self.event_reason,
            self.ss_user_id,
            self.ss_user_email,
        )

    def get_location_details(self):
        """SS GET /api/v2/location/<uuid>. Retrieve the details of a specific
        location given a location uuid.
        """
        return utils._call_url_json(
            f"{self.ss_url}/api/v2/location/{self.location_uuid}",
            headers=self._ss_auth_headers(),
        )

    def list_storage_locations(self):
        """List all Storage Service locations."""
        params = {}
        url = f"{self.ss_url}/api/v2/location/"
        return utils._call_url_json(
            url,
            headers=self._ss_auth_headers(),
            params=json.dumps(params),
            method=utils.METHOD_GET,
        )

    def get_jobs(self):
        """Get a list of jobs ran for a unit (transfer or ingest)."""
        url = f"{self.am_url}/api/v2beta/jobs/{self.unit_uuid}"
        params = {}
        for attribute in ["microservice", "link_uuid", "name"]:
            value = getattr(self, f"job_{attribute}", None)
            if value is not None:
                params[attribute] = value
        return utils._call_url_json(
            url, headers=self._am_auth_headers(), params=params, method=utils.METHOD_GET
        )

    def copy_metadata_files(self, sip_uuid, source_paths):
        """Add metadata files to a SIP using its UUID.

        The `source_paths` parameter must be a list of tuples with
        (location UUID, absolute path).
        """
        url = f"{self.am_url}/api/ingest/copy_metadata_files/"
        params = {
            "sip_uuid": sip_uuid,
            "source_paths[]": [
                base64.b64encode(f"{location_uuid}:{path}".encode())
                for (location_uuid, path) in source_paths
            ],
        }
        return utils._call_url_json(
            url,
            params=params,
            method=utils.METHOD_POST,
            headers=self._am_auth_headers(),
            enhanced_errors=getattr(self, "enhanced_errors", False),
        )

    def create_package(self):
        """Create a transfer using the new API v2 package endpoint."""
        url = f"{self.am_url}/api/v2beta/package/"
        transfer_source = getattr(self, "transfer_source", None)
        if not transfer_source:
            path = self.transfer_directory
        else:
            path = f"{self.transfer_source}:{self.transfer_directory}"
        b64path = base64.b64encode(os.fsencode(path))
        params = {
            "name": self.transfer_name,
            "path": b64path.decode(),
            "type": self.transfer_type,
            "processing_config": self.processing_config,
        }
        return utils._call_url_json(
            url,
            headers=self._am_auth_headers(),
            params=json.dumps(params),
            method=utils.METHOD_POST,
        )

    def validate_csv(self, validator, file_obj):
        """Validates a CSV file against a set of embedded rules. The file to be
        validated is expected to be passed as an open file object (in Python 3+
        a io.TextIOBase instance)."""
        url = f"{self.am_url}/api/v2beta/validate/{validator}/"
        if not (isinstance(file_obj, io.TextIOBase) or hasattr(file_obj, "read")):
            raise TypeError(
                f"Expected an io.TextIOWrapper file object but got {type(file_obj)} instead"
            )
        data = file_obj.read()
        headers = self._am_auth_headers()
        headers.update({"Content-Type": "text/csv; charset=utf-8"})
        encoded_data = data.encode()
        return utils._call_url_json(
            url,
            params=encoded_data,
            method=utils.METHOD_POST,
            headers=headers,
            enhanced_errors=getattr(self, "enhanced_errors", False),
        )

    def extract_file_stream(self):
        """Extract a file, relative to an AIP's path. The primary functionality
        is provided by extract_file below. This helper command exists to change
        the response behavior specifically for the command-line i.e. to enable
        the output of a stream's content directly to stdout.
        """
        self.stream = True
        self.cli_call = True
        return self.extract_file()

    def extract_file(self):
        """Extract a file, relative to an AIP's path.

        If a filename and directory are provided use that information,
        otherwise download the file relative to the directory the script is
        invoked from.

        If stream is True then the raw response is provided to the caller, if
        the caller is an API user. If the caller is the AMClient command-line
        then the stream contents are output to the console.
        """
        self.output_mode = ""  # TODO: don't overwrite mode
        url = f"{self.ss_url}/api/v2/file/{self.package_uuid}/extract_file/?relative_path_to_file={self.relative_path}"
        response = requests.get(url, params=self._ss_auth(), stream=True)
        if getattr(self, "stream", None):
            if getattr(self, "cli_call", None):
                for line in response.iter_content(chunk_size=1024):
                    sys.stdout.write(line)
                return
            return response
        if response.status_code == 200:
            local_filename = getattr(self, "saveas_filename", None)
            if not local_filename:
                local_filename = re.findall(
                    'filename="(.+)"', response.headers["content-disposition"]
                )[0]
            if getattr(self, "directory", None):
                dir_ = self.directory
                if os.path.isdir(dir_):
                    local_filename = os.path.join(dir_, local_filename)
                else:
                    LOGGER.warning(
                        "There is no directory %s; saving %s to %s instead",
                        dir_,
                        local_filename,
                        os.getcwd(),
                    )
            with open(local_filename, "wb") as file_:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file_.write(chunk)
            return response.headers

    def extract_aip_mets_file(self):
        """Extract the METS file for an AIP with provided UUID.

        If stream is True then the raw response is provided to the caller, if
        the caller is an API user. If the caller is the AMClient command-line
        then the stream contents are output to the console.
        """
        self.package_uuid = self.aip_uuid
        package_details = self.get_package(params={"uuid": self.aip_uuid})
        try:
            current_path = package_details["objects"][0]["current_path"]
        except KeyError:
            return errors.ERR_PARSE_JSON
        self.relative_path = utils.relative_path_to_aip_mets_file(
            self.aip_uuid, current_path
        )
        return self.extract_file()

    def list_location_purposes(self):
        """List valid location purposes in the Storage Service."""
        return {
            "AR": "AIP_RECOVERY",
            "AS": "AIP_STORAGE",
            "CP": "CURRENTLY_PROCESSING",
            "DS": "DIP_STORAGE",
            "SD": "SWORD_DEPOSIT",
            "SS": "STORAGE_SERVICE_INTERNAL",
            "BL": "BACKLOG",
            "TS": "TRANSFER_SOURCE",
            "RP": "REPLICATOR",
        }

    def create_location(self):
        """Create a new location in the Storage Service."""
        if self.location_purpose.upper() not in self.list_location_purposes():
            return {
                "error": "location purpose not permitted",
                "valid_purposes": self.list_location_purposes(),
            }
        url = f"{self.ss_url}/api/v2/location/"
        desc = self.location_description if self.location_description else ""
        pipelines = [
            f"/api/v2/pipeline/{pipeline.strip()}/"
            for pipeline in self.pipeline_uuids.split(",")
        ]
        params = {
            "description": desc,
            "pipeline": pipelines,
            "space": f"/api/v2/space/{self.space_uuid}/",
            "default": self.default if self.default else False,
            "purpose": self.location_purpose,
            "relative_path": self.space_relative_path,
        }
        return utils._call_url_json(
            url,
            params=json.dumps(params),
            method=utils.METHOD_POST,
            headers=self._ss_auth_headers(),
        )


def main():
    """Primary entry point of amclient.py"""
    argparser = amclientargs.get_parser()
    # Python 2.x, ensures that help is printed consistently like we see in Python 3.x.
    if len(sys.argv) < 2:
        argparser.print_help()
        sys.exit(0)
    args = argparser.parse_args()
    loggingconfig.setup(args.log_level, args.log_file)
    am_client = AMClient(**vars(args))
    try:
        getattr(am_client, "print_{}".format(args.subcommand.replace("-", "_")))
        print(
            f"{__package__}: Log file can be accessed at: {args.log_file}",
            file=sys.stderr,
        )
    except AttributeError:
        argparser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
