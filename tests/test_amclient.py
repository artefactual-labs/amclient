"""To run the tests::

    $ python -m unittest tests.test_amclient

"""
import collections
import hashlib
import os
import shutil
import sys
import unittest
import uuid
from binascii import hexlify
from contextlib import contextmanager
from io import BytesIO
from unittest import mock

import pytest
import requests
import vcr

from amclient import amclient
from amclient import errors
from amclient import utils


AM_URL = "http://192.168.168.192"
SS_URL = "http://192.168.168.192:8000"
AM_USER_NAME = "test"
AM_API_KEY = "3c23b0361887ace72b9d42963d9acbdf06644673"
SS_USER_NAME = "test"
SS_API_KEY = "5de62f6f4817f903dcfac47fa5cffd44685a2cf2"
TMP_DIR = ".tmp-downloads"
TRANSFER_SOURCE_UUID = "7609101e-15b2-4f4f-a19d-7b23673ac93b"


class TmpDir:
    """Context manager to clear and create a temporary directory and destroy it
    after usage.
    """

    def __init__(self, tmp_dir_path):
        self.tmp_dir_path = tmp_dir_path

    def __enter__(self):
        if os.path.isdir(self.tmp_dir_path):
            shutil.rmtree(self.tmp_dir_path)
        os.makedirs(self.tmp_dir_path)
        return self.tmp_dir_path

    def __exit__(self, exc_type, exc_value, traceback):
        if os.path.isdir(self.tmp_dir_path):
            shutil.rmtree(self.tmp_dir_path)
        if exc_type:
            return None


@contextmanager
def captured_output():
    new_out, new_err = BytesIO(), BytesIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestAMClient(unittest.TestCase):
    """Test runner for AMClient class."""

    @vcr.use_cassette("fixtures/vcr_cassettes/completed_transfers_transfers.yaml")
    def test_completed_transfers_transfers(self):
        """Test getting completed transfers when there are completed transfers
        to get.
        """
        completed_transfers = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).completed_transfers()
        assert (
            completed_transfers["message"]
            == "Fetched completed transfers successfully."
        )
        results = completed_transfers["results"]
        assert isinstance(results, list)
        assert len(results) == 2
        for item in results:
            assert amclient.is_uuid(item)

    @vcr.use_cassette("fixtures/vcr_cassettes/close_completed_transfers_transfers.yaml")
    def test_close_completed_transfers_transfers(self):
        """Test closing completed transfers when there are completed transfers
        to close.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).close_completed_transfers()
        close_succeeded = response["close_succeeded"]
        completed_transfers = response["completed_transfers"]
        assert close_succeeded == completed_transfers
        assert isinstance(close_succeeded, list)
        assert len(close_succeeded) == 2
        for item in close_succeeded:
            assert amclient.is_uuid(item)

    @vcr.use_cassette("fixtures/vcr_cassettes/completed_transfers_no_transfers.yaml")
    def test_completed_transfers_no_transfers(self):
        """Test getting completed transfers when there are no completed
        transfers to get.
        """
        completed_transfers = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).completed_transfers()
        assert (
            completed_transfers["message"]
            == "Fetched completed transfers successfully."
        )
        results = completed_transfers["results"]
        assert isinstance(results, list)
        assert len(results) == 0

    @vcr.use_cassette(
        "fixtures/vcr_cassettes/close_completed_transfers_no_transfers.yaml"
    )
    def test_close_completed_transfers_no_transfers(self):
        """Test closing completed transfers when there are no completed
        transfers to close.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).close_completed_transfers()
        close_succeeded = response["close_succeeded"]
        completed_transfers = response["completed_transfers"]
        assert close_succeeded == completed_transfers
        assert isinstance(close_succeeded, list)
        assert len(close_succeeded) == 0

    @vcr.use_cassette("fixtures/vcr_cassettes/completed_transfers_bad_key.yaml")
    def test_completed_transfers_bad_key(self):
        """Test getting completed transfers when a bad AM API key is
        provided.
        """
        completed_transfers = amclient.AMClient(
            am_api_key="bad api key", am_user_name=AM_USER_NAME, am_url=AM_URL
        ).completed_transfers()
        assert completed_transfers is errors.ERR_INVALID_RESPONSE

    @vcr.use_cassette("fixtures/vcr_cassettes/unapproved_transfers_transfers.yaml")
    def test_unapproved_transfers_transfers(self):
        """Test getting unapproved transfers when there are
        unapproved transfers to get.
        """
        unapproved_transfers = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).unapproved_transfers()
        assert (
            unapproved_transfers["message"]
            == "Fetched unapproved transfers successfully."
        )
        results = unapproved_transfers["results"]
        assert isinstance(results, list)
        assert len(results) == 1
        for unapproved_transfer in results:
            assert "type" in unapproved_transfer
            assert "uuid" in unapproved_transfer
            assert "directory" in unapproved_transfer
            assert amclient.is_uuid(unapproved_transfer["uuid"])

    @vcr.use_cassette("fixtures/vcr_cassettes/unapproved_transfers_no_transfers.yaml")
    def test_unapproved_transfers_no_transfers(self):
        """Test getting unapproved transfers when there are no unapproved
        transfers to get.
        """
        unapproved_transfers = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).unapproved_transfers()
        assert (
            unapproved_transfers["message"]
            == "Fetched unapproved transfers successfully."
        )
        results = unapproved_transfers["results"]
        assert isinstance(results, list)
        assert len(results) == 0

    @vcr.use_cassette("fixtures/vcr_cassettes/transferables.yaml")
    def test_transferables(self):
        """Test that we can get all transferable entities in the Storage
        Service.
        """
        transferables = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            transfer_source=TRANSFER_SOURCE_UUID,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            transfer_path="",
        ).transferables()
        assert isinstance(transferables, dict)
        assert "directories" in transferables
        assert "entries" in transferables
        assert "properties" in transferables
        assert transferables["directories"] == ["ubuntu", "vagrant"]

    @vcr.use_cassette("fixtures/vcr_cassettes/transferables_path.yaml")
    def test_transferables_path(self):
        """Test that we can get all transferable entities in the Storage
        Service under a given path.
        """
        transferables = amclient.AMClient(
            transfer_path=b"vagrant/archivematica-sampledata",
            ss_api_key=SS_API_KEY,
            transfer_source=TRANSFER_SOURCE_UUID,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
        ).transferables()
        assert isinstance(transferables, dict)
        assert "directories" in transferables
        assert "entries" in transferables
        assert "properties" in transferables
        assert transferables["directories"] == [
            "OPF format-corpus",
            "SampleTransfers",
            "TestTransfers",
        ]

    @vcr.use_cassette("fixtures/vcr_cassettes/transferables_bad_path.yaml")
    def test_transferables_bad_path(self):
        """Test that we get empty values when we request all transferable
        entities in the Storage Service with a non-existent path.
        """
        transferables = amclient.AMClient(
            transfer_path=b"vagrant/archivematica-sampledataz",
            ss_api_key=SS_API_KEY,
            transfer_source=TRANSFER_SOURCE_UUID,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
        ).transferables()
        assert isinstance(transferables, dict)
        assert "directories" in transferables
        assert "entries" in transferables
        assert "properties" in transferables
        assert transferables["directories"] == []
        assert transferables["entries"] == []
        assert transferables["properties"] == {}

    @vcr.use_cassette("fixtures/vcr_cassettes/aips_aips.yaml")
    def test_aips_aips(self):
        """Test that we can get all AIPs in the Storage Service.

        Note that for this vcr cassette, the SS TastyPie API was modified to
        return pages of only one package at a time, just to make sure that
        AMClient handles the pagination correctly.
        """
        aips = amclient.AMClient(
            ss_url=SS_URL, ss_user_name=SS_USER_NAME, ss_api_key=SS_API_KEY
        ).aips()
        assert isinstance(aips, list)
        assert len(aips) == 2
        for aip in aips:
            assert isinstance(aip, dict)
            assert "uuid" in aip
            assert amclient.is_uuid(aip["uuid"])
            assert aip["package_type"] == "AIP"
            assert "AIPsStore" in aip["current_full_path"]

    @vcr.use_cassette("fixtures/vcr_cassettes/dips_dips.yaml")
    def test_dips_dips(self):
        """Test that we can get all DIPs in the Storage Service."""
        dips = amclient.AMClient(
            ss_url=SS_URL, ss_user_name=SS_USER_NAME, ss_api_key=SS_API_KEY
        ).dips()
        assert isinstance(dips, list)
        assert len(dips) == 2
        for dip in dips:
            assert isinstance(dip, dict)
            assert "uuid" in dip
            assert amclient.is_uuid(dip["uuid"])
            assert dip["package_type"] == "DIP"
            assert "DIPsStore" in dip["current_full_path"]

    @vcr.use_cassette("fixtures/vcr_cassettes/dips_no_dips.yaml")
    def test_dips_no_dips(self):
        """Test that we get no DIPs from the Storage Service if there are none."""
        dips = amclient.AMClient(
            ss_url=SS_URL, ss_user_name=SS_USER_NAME, ss_api_key=SS_API_KEY
        ).dips()
        assert isinstance(dips, list)
        assert dips == []

    @vcr.use_cassette("fixtures/vcr_cassettes/aips2dips.yaml")
    def test_aips2dips(self):
        """Test that we can get all AIPs in the Storage Service and their
        corresonding DIPs.
        """
        aips2dips = amclient.AMClient(
            ss_url=SS_URL, ss_user_name=SS_USER_NAME, ss_api_key=SS_API_KEY
        ).aips2dips()
        assert isinstance(aips2dips, dict)
        assert len(aips2dips) == 4
        assert aips2dips["3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b"] == []
        assert aips2dips["979cce65-2a6f-407f-a49c-1bcf13bd8571"] == []
        assert aips2dips["721b98b9-b894-4cfb-80ab-624e52263300"] == [
            "c0e37bab-e51e-482d-a066-a277330de9a7"
        ]
        assert aips2dips["99bb20ee-69c6-43d0-acf0-c566020357d2"] == [
            "7e49afa4-116b-4650-8bbb-9341906bdb21"
        ]

    @vcr.use_cassette("fixtures/vcr_cassettes/aip2dips_dip.yaml")
    def test_aip2dips_dips(self):
        """Test that we can get all of the DIPs from the Storage Service for a
        given AIP.
        """
        aip_uuid = "721b98b9-b894-4cfb-80ab-624e52263300"
        dip_uuid = "c0e37bab-e51e-482d-a066-a277330de9a7"
        dips = amclient.AMClient(
            aip_uuid=aip_uuid,
            ss_url=SS_URL,
            ss_user_name=SS_USER_NAME,
            ss_api_key=SS_API_KEY,
        ).aip2dips()
        assert isinstance(dips, list)
        assert len(dips) == 1
        dip = dips[0]
        assert isinstance(dip, dict)
        assert dip["package_type"] == "DIP"
        assert dip["uuid"] == dip_uuid

    @vcr.use_cassette("fixtures/vcr_cassettes/aip2dips_no_dip.yaml")
    def test_aip2dips_no_dips(self):
        """Test that we get no DIPs when attempting to get all DIPs
        corresponding to an AIP that has none.
        """
        aip_uuid = "3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b"
        dips = amclient.AMClient(
            aip_uuid=aip_uuid,
            ss_url=SS_URL,
            ss_user_name=SS_USER_NAME,
            ss_api_key=SS_API_KEY,
        ).aip2dips()
        assert isinstance(dips, list)
        assert len(dips) == 0

    @vcr.use_cassette("fixtures/vcr_cassettes/download_dip_dip.yaml")
    def test_download_dip_dip(self):
        """Test that we can download a DIP when there is one."""
        with TmpDir(TMP_DIR):
            dip_uuid = "c0e37bab-e51e-482d-a066-a277330de9a7"
            dip_path = amclient.AMClient(
                dip_uuid=dip_uuid,
                ss_url=SS_URL,
                ss_user_name=SS_USER_NAME,
                ss_api_key=SS_API_KEY,
                directory=TMP_DIR,
            ).download_dip()
            assert (
                dip_path == f"{TMP_DIR}/package-c0e37bab-e51e-482d-a066-a277330de9a7.7z"
            )
            assert os.path.isfile(dip_path)

    @vcr.use_cassette("fixtures/vcr_cassettes/download_dip_no_dip.yaml")
    def test_download_dip_no_dip(self):
        """Test that we can try to download a DIP that does not exist."""
        dip_uuid = "bad dip uuid"
        dip_path = amclient.AMClient(
            dip_uuid=dip_uuid,
            ss_url=SS_URL,
            ss_user_name=SS_USER_NAME,
            ss_api_key=SS_API_KEY,
        ).download_dip()
        assert dip_path is None

    @vcr.use_cassette("fixtures/vcr_cassettes/download_aip_success.yaml")
    def test_download_aip_success(self):
        """Test that we can download an AIP when there is one."""
        with TmpDir(TMP_DIR):
            aip_uuid = "216dd8a6-c366-41f8-b11e-0c70814b3992"
            transfer_name = "transfer"
            # Changing the SS_API_KEY global var to generate the cassetes
            # for the new test cases makes all the other cassetes to fail.
            # Adding a local var to be able to generate the new cassetes.
            ss_api_key = "7021334bee4c9155c07e531608dd28a9d8039420"
            aip_path = amclient.AMClient(
                aip_uuid=aip_uuid,
                ss_url=SS_URL,
                ss_user_name=SS_USER_NAME,
                ss_api_key=ss_api_key,
                directory=TMP_DIR,
            ).download_aip()
            assert aip_path == f"{TMP_DIR}/{transfer_name}-{aip_uuid}.7z"
            assert os.path.isfile(aip_path)

    @vcr.use_cassette("fixtures/vcr_cassettes/download_aip_fail.yaml")
    def test_download_aip_fail(self):
        """Test that we can try to download an AIP that does not exist."""
        aip_uuid = "bad-aip-uuid"
        # Changing the SS_API_KEY global var to generate the cassetes
        # for the new test cases makes all the other cassetes to fail.
        # Adding a local var to be able to generate the new cassetes.
        ss_api_key = "7021334bee4c9155c07e531608dd28a9d8039420"
        aip_path = amclient.AMClient(
            aip_uuid=aip_uuid,
            ss_url=SS_URL,
            ss_user_name=SS_USER_NAME,
            ss_api_key=ss_api_key,
        ).download_aip()
        assert aip_path is None

    @vcr.use_cassette("fixtures/vcr_cassettes/delete_aip_success.yaml")
    def test_delete_aip_success(self):
        """Test that we can request deletion of existing AIP."""
        aip_uuid = "fccc77cf-2045-44ed-9ddc-b335c63d5f9a"
        pipeline_uuid = "a49dce91-3dca-4228-a271-0327ea89afb6"
        response = amclient.AMClient(
            aip_uuid=aip_uuid,
            ss_url=SS_URL,
            ss_user_name=SS_USER_NAME,
            ss_api_key=SS_API_KEY,
            pipeline_uuid=pipeline_uuid,
            event_reason="Testing that deletion request works",
            ss_user_id="1",
            ss_user_email="test@example.com",
        ).delete_aip()
        assert response["message"] == "Delete request created successfully."

    @vcr.use_cassette("fixtures/vcr_cassettes/delete_aip_fail.yaml")
    def test_delete_aip_fail(self):
        """Test that we can try to delete an AIP that does not exist."""
        aip_uuid = "bad-aip-uuid"
        pipeline_uuid = "a49dce91-3dca-4228-a271-0327ea89afb6"
        response = amclient.AMClient(
            aip_uuid=aip_uuid,
            ss_url=SS_URL,
            ss_user_name=SS_USER_NAME,
            ss_api_key=SS_API_KEY,
            pipeline_uuid=pipeline_uuid,
            event_reason="Testing when deletion request doesn't work",
            ss_user_id="1",
            ss_user_email="test@example.com",
        ).delete_aip()
        assert response == errors.ERR_INVALID_RESPONSE

    @vcr.use_cassette("fixtures/vcr_cassettes/completed_ingests_ingests.yaml")
    def test_completed_ingests_ingests(self):
        """Test getting completed ingests when there are completed ingests
        to get.
        """
        completed_ingests = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).completed_ingests()
        assert completed_ingests["message"] == "Fetched completed ingests successfully."
        results = completed_ingests["results"]
        assert isinstance(results, list)
        assert len(results) == 2
        for item in results:
            assert amclient.is_uuid(item)

    @vcr.use_cassette("fixtures/vcr_cassettes/close_completed_ingests_ingests.yaml")
    def test_close_completed_ingests_ingests(self):
        """Test closing completed ingests when there are completed ingests
        to close.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).close_completed_ingests()
        close_succeeded = response["close_succeeded"]
        completed_ingests = response["completed_ingests"]
        assert close_succeeded == completed_ingests
        assert isinstance(close_succeeded, list)
        assert len(close_succeeded) == 2
        for item in close_succeeded:
            assert amclient.is_uuid(item)

    @vcr.use_cassette("fixtures/vcr_cassettes/test_hide_units.yaml")
    def test_hide_units(self):
        """Test the hiding of a unit type (transfer or ingest) via the
        Archivematica API.
        """
        Result = collections.namedtuple("Result", "uuid unit_type expected data_type")
        hide_tests = [
            Result(
                uuid="fdf1f7d4-7b0e-46d7-a1cc-e1851f8b92ed",
                unit_type="transfer",
                expected={"removed": True},
                data_type=dict,
            ),
            Result(
                uuid="777a9d9e-baad-f00d-8c7e-00b75773672d",
                unit_type="transfer",
                expected=errors.ERR_INVALID_RESPONSE,
                data_type=int,
            ),
            Result(
                uuid="b72afa68-9e82-410d-9235-02fa10512e14",
                unit_type="ingest",
                expected={"removed": True},
                data_type=dict,
            ),
            Result(
                uuid="777a9d9e-baad-f00d-8c7e-00b75773672d",
                unit_type="ingest",
                expected=errors.ERR_INVALID_RESPONSE,
                data_type=int,
            ),
        ]
        for test in hide_tests:
            response = amclient.AMClient(
                am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
            ).hide_unit(test.uuid, test.unit_type)
            assert isinstance(response, test.data_type)
            assert response == test.expected

    @vcr.use_cassette("fixtures/vcr_cassettes/completed_ingests_no_ingests.yaml")
    def test_completed_ingests_no_ingests(self):
        """Test getting completed ingests when there are no completed
        ingests to get.
        """
        completed_ingests = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).completed_ingests()
        assert completed_ingests["message"] == "Fetched completed ingests successfully."
        results = completed_ingests["results"]
        assert isinstance(results, list)
        assert len(results) == 0

    @vcr.use_cassette("fixtures/vcr_cassettes/close_completed_ingests_no_ingests.yaml")
    def test_close_completed_ingests_no_ingests(self):
        """Test closing completed ingests when there are no completed
        ingests to close.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        ).close_completed_ingests()
        close_succeeded = response["close_succeeded"]
        completed_ingests = response["completed_ingests"]
        assert close_succeeded == completed_ingests
        assert isinstance(close_succeeded, list)
        assert len(close_succeeded) == 0

    @vcr.use_cassette("fixtures/vcr_cassettes/pipeline.yaml")
    def test_get_pipelines(self):
        """Test getting the pipelines available to the storage service where
        there is at least one pipeline available to the service.
        """
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY, ss_user_name=SS_USER_NAME, ss_url=SS_URL
        ).get_pipelines()

        objects = response["objects"]
        pipelines = objects[0]["uuid"]
        resource_uri = objects[0]["resource_uri"]
        assert amclient.is_uuid(pipelines)
        assert resource_uri == "/api/v2/pipeline/f914af05-c7d2-4611-b2eb-61cd3426d9d2/"
        assert isinstance(objects, list)
        assert len(objects) > 0

    @vcr.use_cassette("fixtures/vcr_cassettes/pipeline_none.yaml")
    def test_get_pipelines_none(self):
        """Test getting the pipelines available to the storage service where
        there is at least one pipeline available to the service.
        """
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY, ss_user_name=SS_USER_NAME, ss_url=SS_URL
        ).get_pipelines()

        objects = response["objects"]
        assert objects == []
        assert isinstance(objects, list)
        assert len(objects) == 0

    @vcr.use_cassette("fixtures/vcr_cassettes/transfer_status.yaml")
    def test_get_transfer_status(self):
        """Test the successful return of the status of a transfer for a
        valid transfer UUID.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_uuid="63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9",
        ).get_transfer_status()

        status = response["status"]
        message = response["message"]
        assert status == "COMPLETE"
        assert message == (
            "Fetched status for 63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9 successfully."
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/transfer_status_invalid_uuid.yaml")
    def test_get_transfer_status_invalid_uuid(self):
        """Test the successful return of the status for a non-existant
        transfer in Archivematica.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_uuid="7bffc8f7-baad-f00d-8120-b1c51c2ab5db",
        ).get_transfer_status()
        message = response["message"]
        message_type = response["type"]
        assert message == (
            "Cannot fetch unitTransfer with UUID 7bffc8f7-"
            "baad-f00d-8120-b1c51c2ab5db"
        )
        assert message_type == "transfer"

    @vcr.use_cassette("fixtures/vcr_cassettes/ingest_status.yaml")
    def test_get_ingest_status(self):
        """Test the successful return of the status of an ingest for a
        valid SIP UUID.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            sip_uuid="23129471-09e3-467e-88b6-eb4714afb5ac",
        ).get_ingest_status()
        message = response["message"]
        message_type = response["type"]
        assert message == (
            "Fetched status for 23129471-09e3-467e-88b6-eb4714afb5ac successfully."
        )
        assert message_type == "SIP"

    @vcr.use_cassette("fixtures/vcr_cassettes/ingest_status_invalid_uuid.yaml")
    def test_get_ingest_status_invalid_uuid(self):
        """Test the response from the server for a request to find the status
        of an ingest uuid that doesn't exist.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            sip_uuid="63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9",
        ).get_ingest_status()
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/test_get_existing_processing_config.yaml")
    def test_get_processing_config(self):
        """Test retrieval of the default Processing MCP Config file from the
        Archivematica instance.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            processing_config="default",
        ).get_processing_config()
        processing_mcp_file = response
        assert "<processingMCP>" and "</processingMCP>" in processing_mcp_file

    @vcr.use_cassette(
        "fixtures/vcr_cassettes/test_get_non_existing_processing_config.yaml"
    )
    def test_get_non_existing_processing_config(self):
        """Test retrieval of a Processing MCP Config file that does not exist
        in the Archivematica instance. Archivematica returns a 404 error and
        a HTML result. This test is volatile to both changes in AM's handling
        of this request failure in future, and changes to the error handling
        in AMClient.py.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            processing_config="badf00d",
        ).get_processing_config()
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/approve_existing_transfer.yaml")
    def test_approve_transfer(self):
        """Test the approval of a transfer waiting in the Archivematica
        pipeline."""
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_directory="approve_1",
            transfer_type="standard",
        ).approve_transfer()
        message = response["message"]
        uuid = response["uuid"]
        assert message == "Approval successful."
        assert amclient.is_uuid(uuid)

    @vcr.use_cassette("fixtures/vcr_cassettes/approve_non_existing_transfer.yaml")
    def test_approve_non_existing_transfer(self):
        """If a transfer isn't available for us to approve, test the response
        from AMClient.py. The response is a 404 and this is handled
        specifically by utils.py and the return is an error code.
        """
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_directory="approve_2",
            transfer_type="standard",
        ).approve_transfer()
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/reingest_existing_aip.yaml")
    def test_reingest_aip(self):
        """Test amclient's ability to initiate the reingest of an AIP."""
        pipeline_uuid = "65aaac5d-b4fd-478e-967b-6cdfee02f2c5"
        aip_uuid = "df8e0c68-3bda-4d1d-8493-789f7dec47f5"
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            pipeline_uuid=pipeline_uuid,
            aip_uuid=aip_uuid,
            reingest_type="standard",
            processing_config="default",
        ).reingest_aip()
        error = response["error"]
        message = response["message"]
        assert error is False
        assert message == (
            "Package {aip_uuid} sent "
            "to pipeline Archivematica on 4e2f66a7a29f "
            "({pipeline_uuid}) for re-ingest".format(
                aip_uuid=aip_uuid, pipeline_uuid=pipeline_uuid
            )
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/reingest_non_existing_aip.yaml")
    def test_reingest_non_aip(self):
        """Test amclient's response to the initiation of a reingest for an AIP
        that does not exist.
        """
        pipeline_uuid = "bb033eff-131e-48d5-980f-c4edab0cb038"
        aip_uuid = "bb033eff-131e-48d5-980f-c4edab0cb038"
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            pipeline_uuid=pipeline_uuid,
            aip_uuid=aip_uuid,
            reingest_type="standard",
            processing_config="default",
        ).reingest_aip()
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/get_package_details.yaml")
    def test_get_package_details(self):
        """Test that amclient can retrieve details about a package."""
        package_uuid = "23129471-09e3-467e-88b6-eb4714afb5ac"
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            package_uuid=package_uuid,
        ).get_package_details()
        status = response["status"]
        package_type = response["package_type"]
        assert status == "UPLOADED"
        assert package_type == "AIP"

    @vcr.use_cassette("fixtures/vcr_cassettes/get_package_details_invalid_uuid.yaml")
    def test_get_package_details_invalid_uuid(self):
        """Test amlient's response when an invalid package uuid is provided to
        the get package details endpoint.
        """
        package_uuid = "23129471-baad-f00d-88b6-eb4714afb5ac"
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            package_uuid=package_uuid,
        ).get_package_details()
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/get_all_compressed_aips.yaml")
    def test_get_all_compressed_aips(self):
        """Test amclient's ability to report on all compressed AIPs in the
        storage service.
        """
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY, ss_user_name=SS_USER_NAME, ss_url=SS_URL
        ).get_all_compressed_aips()
        expected_list = [
            "6d32a85f-6715-43af-947c-83c9d7f0deac",
            "6f198696-e3b6-4f45-8ab3-b4cd4afd921a",
            "9c5edcdc-3e3f-499d-a016-a43b9db875b1",
        ]
        assert set(response.keys()) == set(expected_list)
        for aip in response.values():
            assert aip["uuid"] in expected_list

    @vcr.use_cassette("fixtures/vcr_cassettes/get_default_locations.yaml")
    def test_get_default_storage_locations(self):
        """Test that amclient can successfully retrieve Archivematica's default
        storage locations.
        """
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY, ss_user_name=SS_USER_NAME, ss_url=SS_URL
        ).list_storage_locations()
        count = response.get("meta").get("total_count")
        if not count:
            assert False, "Cannot retrieve storage location count"
        assert len(response.get("objects", [])) == count, (
            "Failed to count the storage locations available and make the "
            "comparison with metadata"
        )
        purposes = ["TS", "AS", "DS", "BL", "SS", "AR", "CP"]
        listed_purposes = [p.get("purpose") for p in response.get("objects")]
        assert set(listed_purposes) == set(purposes), (
            "Unable to retrieve and validate some basic information about "
            "the storage locations returned"
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/test_package_endpoint.yaml")
    def test_create_package_endpoint(self):
        """Test the package endpoint to ensure that it returns a UUID that we
        can then work with to monitor potential transfers. We don't get much
        feedback from the v2/beta endpoint so we just check that we do receive
        a UUID as anticipated.
        """
        path = "/archivematica/archivematica-sampledata/SampleTransfers/DemoTransfer"
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_source="d1184f7f-d755-4c8d-831a-a3793b88f760",
            transfer_directory=path,
            transfer_name="amclient-transfer",
            processing_config="automated",
        ).create_package()
        uuid_ = response.get("id", "")
        try:
            uuid.UUID(uuid_, version=4)
        except ValueError:
            assert False
        # Provide a test for an absolute path, over relative above.
        path = (
            "/home/archivematica/archivematica-sampledata/SampleTransfers/"
            "DemoTransfer"
        )
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_directory=path,
            transfer_name="amclient-transfer",
            processing_config="automated",
        ).create_package()
        uuid_ = response.get("id", "")
        try:
            uuid.UUID(uuid_, version=4)
        except ValueError:
            assert False
        # Provide a test for a non-standard transfer type
        path = "/archivematica/archivematica-sampledata/SampleTransfers/BagTransfer"
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            transfer_source="d1184f7f-d755-4c8d-831a-a3793b88f760",
            transfer_directory=path,
            transfer_name="amclient-transfer",
            transfer_type="unzipped bag",
            processing_config="automated",
        ).create_package()
        uuid_ = response.get("id", "")
        try:
            uuid.UUID(uuid_, version=4)
        except ValueError:
            assert False

    @vcr.use_cassette("fixtures/vcr_cassettes/test_extract_individual_file.yaml")
    def test_extract_individual_file(self):
        """Test the result of downloading an individual file from a package in
        the storage service.
        """
        with TmpDir(TMP_DIR):
            filename_to_test = "bird.mp3"
            package_uuid = "2ad1bf0d-23fa-44e0-a128-9feadfe22c42"
            path = "amclient-transfer_1-{}/data/objects/{}".format(
                package_uuid, filename_to_test
            )
            filename = "bird_download.mp3"
            response = amclient.AMClient(
                ss_api_key=SS_API_KEY,
                ss_user_name=SS_USER_NAME,
                ss_url=SS_URL,
                package_uuid=package_uuid,
                relative_path=path,
                saveas_filename=filename,
                directory=TMP_DIR,
            ).extract_file()
            file_ = os.path.join(TMP_DIR, filename)
            assert os.path.isfile(file_)
            assert os.path.getsize(file_) == int(response.get("Content-Length", 0))
            assert filename_to_test in response.get("Content-Disposition", "")

    @vcr.use_cassette("fixtures/vcr_cassettes/test_extract_individual_file.yaml")
    def test_extract_and_stream_individual_file(self):
        """Test the result of downloading an individual file from a package in
        the storage service.
        """
        with TmpDir(TMP_DIR):
            filename_to_test = "bird.mp3"
            package_uuid = "2ad1bf0d-23fa-44e0-a128-9feadfe22c42"
            path = "amclient-transfer_1-{}/data/objects/{}".format(
                package_uuid, filename_to_test
            )
            response = amclient.AMClient(
                ss_api_key=SS_API_KEY,
                ss_user_name=SS_USER_NAME,
                ss_url=SS_URL,
                package_uuid=package_uuid,
                relative_path=path,
                stream=True,
            ).extract_file()
            # We have a stream, check we have an iterator and some content.
            assert (
                hexlify(next(response.iter_content(chunk_size=14)))
                == b"49443303000000001f7654495432"
            )
            assert response.headers.get("Content-Length") == "5992608"
            assert filename_to_test in response.headers.get("Content-Disposition", "")

    @vcr.use_cassette("fixtures/vcr_cassettes/test_extract_individual_file.yaml")
    def test_extract_and_stream_individual_file_cli(self):
        """Test the result of downloading an individual file from a package in
        the storage service. Specifically if via the CLI.
        """
        with TmpDir(TMP_DIR):
            filename_to_test = "bird.mp3"
            package_uuid = "2ad1bf0d-23fa-44e0-a128-9feadfe22c42"
            path = "amclient-transfer_1-{}/data/objects/{}".format(
                package_uuid, filename_to_test
            )
            with captured_output() as (out, err):
                amclient.AMClient(
                    ss_api_key=SS_API_KEY,
                    ss_user_name=SS_USER_NAME,
                    ss_url=SS_URL,
                    package_uuid=package_uuid,
                    relative_path=path,
                    stream=True,
                ).extract_file_stream()
            stdout = out.getvalue()
            assert b"ID3\x03\x00\x00\x00\x00\x1fvTIT2" in stdout
            assert len(stdout) == 5992608
            # We are working with archival objects, lets make sure the return
            # is as robust as possible, i.e. no stray bytes.
            assert hashlib.md5(stdout).hexdigest() == "7f42199657dea535b6ad1963a6c7a2ac"

    @vcr.use_cassette("fixtures/vcr_cassettes/test_extract_aip_mets_file.yaml")
    def test_extract_aip_mets_file(self):
        """Test the result of downloading an individual file from a package in
        the storage service.
        """
        with TmpDir(TMP_DIR):
            package_uuid = "64f4cb73-60bc-49f2-ab75-d83c9365b7d3"
            am = amclient.AMClient(
                ss_api_key=SS_API_KEY,
                ss_user_name=SS_USER_NAME,
                ss_url=SS_URL,
                directory=TMP_DIR,
            )
            am.aip_uuid = package_uuid
            response = am.extract_aip_mets_file()
            mets_filename = f"METS.{package_uuid}.xml"
            file_ = os.path.join(TMP_DIR, mets_filename)
            assert os.path.isfile(file_)
            assert os.path.getsize(file_) == 119107
            assert mets_filename in response.get("Content-Disposition", "")

    @vcr.use_cassette("fixtures/vcr_cassettes/jobs.yaml")
    def test_get_jobs(self):
        """Test getting the jobs ran for a transfer"""
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            unit_uuid="ca480d94-892c-4d99-bbb1-290698406571",
        ).get_jobs()
        assert isinstance(response, list)
        assert len(response) > 0
        expected_job_attributes = [
            "link_uuid",
            "microservice",
            "name",
            "status",
            "tasks",
            "uuid",
        ]
        expected_task_attributes = ["exit_code", "uuid"]
        for job in response:
            assert sorted(job.keys()) == expected_job_attributes
            for task in job["tasks"]:
                assert sorted(task.keys()) == expected_task_attributes
        # Test filtering jobs by microservice
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            unit_uuid="ca480d94-892c-4d99-bbb1-290698406571",
            job_microservice="Clean up names",
        ).get_jobs()
        expected_jobs = [
            "Sanitize Transfer name",
            "Sanitize object's file and directory names",
        ]
        microservice_jobs = sorted(job["name"] for job in response)
        assert microservice_jobs == expected_jobs
        # Test filtering jobs by link_uuid
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            unit_uuid="ca480d94-892c-4d99-bbb1-290698406571",
            job_link_uuid="87e7659c-d5de-4541-a09c-6deec966a0c0",
        ).get_jobs()
        assert len(response) == 1
        assert response[0]["name"] == "Verify mets_structmap.xml compliance"
        # Test filtering jobs by name
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            unit_uuid="ca480d94-892c-4d99-bbb1-290698406571",
            job_name="Verify metadata directory checksums",
        ).get_jobs()
        assert len(response) == 1
        assert response[0]["name"] == "Verify metadata directory checksums"

    @mock.patch("requests.request")
    def test_get_status(self, mock_request):
        transfer_uuid = "ca480d94-892c-4d99-bbb1-290698406571"
        sip_uuid = "e8e13e0c-1b26-451a-a343-38ae5b8c3d3e"
        client = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        )

        # get_unit_status finds the status of in-progress transfers.
        mock_request.return_value.json.return_value = {"status": "PROCESSING"}
        client.get_unit_status(transfer_uuid)
        mock_request.assert_called_once_with(
            "GET",
            data=None,
            headers=client._am_auth_headers(),
            params=None,
            url=f"{client.am_url}/api/transfer/status/{transfer_uuid}",
        )
        mock_request.reset_mock()

        # get_unit_status finds the status of backlogged transfers.
        mock_request.return_value.json.return_value = {
            "status": "COMPLETE",
            "sip_uuid": "BACKLOG",
        }
        client.get_unit_status(transfer_uuid)
        mock_request.assert_called_once_with(
            "GET",
            data=None,
            headers=client._am_auth_headers(),
            params=None,
            url=f"{client.am_url}/api/transfer/status/{transfer_uuid}",
        )
        mock_request.reset_mock()

        # get_unit_status finds the status of transfers moved to ingest,
        # resulting in two API calls (transfer and ingest).
        mock_request.return_value.json.return_value = {
            "status": "COMPLETE",
            "sip_uuid": sip_uuid,
        }
        client.get_unit_status(transfer_uuid)
        assert mock_request.call_count == 2
        mock_request.assert_any_call(
            "GET",
            data=None,
            headers=client._am_auth_headers(),
            params=None,
            url=f"{client.am_url}/api/transfer/status/{transfer_uuid}",
        )
        mock_request.assert_any_call(
            "GET",
            data=None,
            headers=client._am_auth_headers(),
            params=None,
            url=f"{client.am_url}/api/ingest/status/{sip_uuid}",
        )
        mock_request.reset_mock()

        # get_unit_status raises errors generated by requests.
        mock_request.side_effect = requests.exceptions.Timeout
        with self.assertRaises(requests.exceptions.Timeout):
            client.get_unit_status(transfer_uuid)
        mock_request.reset_mock()

    @vcr.use_cassette("fixtures/vcr_cassettes/create_location.yaml")
    def test_create_location(self):
        """Test the response from the create location function for calls we
        expect to succeed.
        """

        pipeline_uri_pattern = "/api/v2/pipeline/"
        space_uri_pattern = "/api/v2/space/"

        purpose_transfer = "TS"
        purpose_aip_storage = "AS"
        purpose_dip_storage = "DS"

        test_desc = "AM Client unit test description"
        test_path_1 = os.path.join("this", "is", "a", "path")
        test_path_2 = os.path.join("this", "is", "another", "path")
        pipeline_uuid_1 = "d6aeb4e0-e836-4768-8225-26e5720950d3"
        pipeline_uuid_2 = "26bda073-753b-42bd-b312-f39b7db4921d"
        uri_pipeline_1 = f"{pipeline_uri_pattern}{pipeline_uuid_1}/"
        uri_pipeline_2 = f"{pipeline_uri_pattern}{pipeline_uuid_2}/"
        space_uuid = "30226523-c759-443f-95c9-0fa813034731"
        uri_space = f"{space_uri_pattern}{space_uuid}/"

        # Create a transfer-source and assign it to two pipelines.
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            location_purpose=purpose_transfer,
            location_description=test_desc,
            pipeline_uuids=f"{pipeline_uuid_1},{pipeline_uuid_2}",
            space_uuid=space_uuid,
            default=False,
            space_relative_path=test_path_1,
        ).create_location()

        assert (
            response.get("description") == test_desc
        ), "Description returned is incorrect"
        assert (
            response.get("relative_path") == test_path_1
        ), "Path returned is incorrect"
        assert uri_pipeline_1 and uri_pipeline_2 in response.get(
            "pipeline"
        ), "The specified pipelines are not in the API response"
        assert response.get(
            "resource_uri"
        ), "Resource URI is not in response as expected"
        assert response.get("uuid"), "UUID for the new location not returned"
        assert (
            response.get("default") is False
        ), "Space default has returned incorrectly"
        assert (
            response.get("purpose") == purpose_transfer
        ), "Incorrect purpose assigned to newly created location"
        assert (
            response.get("space") == uri_space
        ), "Incorrect URI for our space returned"

        # Create an archival storage location and assign it to one pipeline.
        # Make default.
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            location_purpose=purpose_aip_storage,
            location_description="AM Client unit test description",
            pipeline_uuids=pipeline_uuid_1,
            space_uuid=space_uuid,
            default=True,
            space_relative_path=test_path_2,
        ).create_location()

        assert response.get("relative_path") == test_path_2
        assert uri_pipeline_1 in response.get("pipeline")
        assert len(response.get("pipeline")) == 1
        assert response.get("default") is True
        assert (
            response.get("purpose") == purpose_aip_storage
        ), "Incorrect purpose assigned to newly created location"

        # Create a DIP storage location and provide no description.
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            location_purpose=purpose_dip_storage,
            location_description="",
            pipeline_uuids=pipeline_uuid_1,
            space_uuid=space_uuid,
            default=False,
            space_relative_path=test_path_1,
        ).create_location()

        assert response.get("description") == ""
        assert (
            response.get("purpose") == purpose_dip_storage
        ), "Incorrect purpose assigned to newly created location"

    @vcr.use_cassette("fixtures/vcr_cassettes/create_location_failures.yaml")
    def test_create_location_failure_responses(self):
        """Test various calls that we don't expect to succeed using AMClient."""

        purpose_aip_storage = "AS"
        purpose_dip_storage = "DS"
        purpose_non_existent = "ZZ"

        test_desc = "AM Client unit test description"
        test_path_1 = os.path.join("this", "is", "a", "path")
        pipeline_uuid_1 = "d6aeb4e0-e836-4768-8225-26e5720950d3"
        bad_pipeline_uuid = "badf00d3-753b-42bd-b312-f39b7db4921d"
        space_uuid = "30226523-c759-443f-95c9-0fa813034731"
        bad_space_uuid = "badf00d3-c759-443f-95c9-0fa813034731"

        # Try to create a transfer source with invalid space.
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            location_purpose=purpose_aip_storage,
            location_description=test_desc,
            pipeline_uuids=pipeline_uuid_1,
            space_uuid=bad_space_uuid,
            default=False,
            space_relative_path=test_path_1,
        ).create_location()

        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        ), "Incorrect error code returned from AMClient"

        # Try to create a transfer source with invalid pipeline.
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            location_purpose=purpose_dip_storage,
            location_description=test_desc,
            pipeline_uuids=bad_pipeline_uuid,
            space_uuid=space_uuid,
            default=False,
            space_relative_path=test_path_1,
        ).create_location()

        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        ), "Incorrect error code returned from AMClient"

        # Try to create a location with an invalid location type.
        response = amclient.AMClient(
            ss_api_key=SS_API_KEY,
            ss_user_name=SS_USER_NAME,
            ss_url=SS_URL,
            location_purpose=purpose_non_existent,
            location_description=test_desc,
            pipeline_uuids=pipeline_uuid_1,
            space_uuid=space_uuid,
            default=False,
            space_relative_path=test_path_1,
        ).create_location()

        assert (
            response.get("valid_purposes")
            == amclient.AMClient().list_location_purposes()
        )

    @mock.patch("requests.request")
    def test_validate_csv(self, mock_request):
        client = amclient.AMClient(
            am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
        )
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "fixtures",
            "validate_me.csv",
        )
        expected_headers = client._am_auth_headers()
        expected_headers.update({"Content-Type": "text/csv; charset=utf-8"})

        file_obj = open(filepath)
        file_contents = file_obj.read()

        # file is valid
        mock_request.return_value.json.return_value = {"valid": "true"}
        for validator in ["avalon", "rights"]:
            file_obj.seek(0)  # reset cursor so read() produces desired data
            assert client.validate_csv(validator, file_obj) == {"valid": "true"}
            mock_request.assert_called_once_with(
                "POST",
                data=file_contents.encode("utf-8"),
                params=None,
                headers=expected_headers,
                url=f"{client.am_url}/api/v2beta/validate/{validator}/",
            )
            mock_request.reset_mock()

        # file is invalid
        http_error = requests.exceptions.HTTPError()
        error_message = {"valid": False, "reason": "A required field is missing."}
        http_error.response = mock.Mock()
        http_error.response.json.return_value = error_message
        mock_request.side_effect = http_error
        client.enhanced_errors = True
        for validator in ["avalon", "rights"]:
            file_obj.seek(0)  # reset cursor so read() produces desired data
            result = client.validate_csv(validator, file_obj)
            assert result == errors.ERR_INVALID_RESPONSE
            assert result.message == error_message
            mock_request.assert_called_once_with(
                "POST",
                data=file_contents.encode("utf-8"),
                params=None,
                headers=expected_headers,
                url=f"{client.am_url}/api/v2beta/validate/{validator}/",
            )
            mock_request.reset_mock()

        file_obj.close()

        # file is wrong type
        with pytest.raises(TypeError):
            client.validate_csv("avalon", filepath)

    @vcr.use_cassette("fixtures/vcr_cassettes/approve_existing_partial_reingest.yaml")
    def test_approve_partial_reingest(self):
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            sip_uuid="7d41223f-76af-4732-96a9-fb06aa5feaed",
        ).approve_partial_reingest()
        assert response["message"] == "Approval successful."

    @vcr.use_cassette(
        "fixtures/vcr_cassettes/approve_non_existing_partial_reingest.yaml"
    )
    def test_approve_non_existing_partial_reingest(self):
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            sip_uuid="4ceaf490-cf9b-425a-adb7-8358a7a68fa9",
        ).approve_partial_reingest()
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )

    @vcr.use_cassette("fixtures/vcr_cassettes/copy_metadata_files.yaml")
    def test_copy_metadata_files(self):
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
        ).copy_metadata_files(
            "f8beb140-3149-471c-861a-249e1d851c92",
            [
                (
                    "4d0de0aa-2658-4f21-bb09-d730b84b2b01",
                    "/home/archivematica/archivematica-sampledata/metadata.csv",
                ),
                (
                    "4d0de0aa-2658-4f21-bb09-d730b84b2b01",
                    "/home/archivematica/archivematica-sampledata/mdupdate.zip",
                ),
            ],
        )
        assert response["message"] == "Metadata files added successfully."

    def _test_copy_metadata_files_with_empty_parameter(self, *params):
        response = amclient.AMClient(
            am_api_key=AM_API_KEY,
            am_user_name=AM_USER_NAME,
            am_url=AM_URL,
            enhanced_errors=True,
        ).copy_metadata_files(*params)
        assert (
            errors.error_lookup(response)
            == errors.error_codes[errors.ERR_INVALID_RESPONSE]
        )
        assert response.message == {
            "error": True,
            "message": "sip_uuid and source_paths[] both required.",
        }

    @vcr.use_cassette(
        "fixtures/vcr_cassettes/copy_metadata_files_with_empty_sip_uuid.yaml",
    )
    def test_copy_metadata_files_with_empty_sip_uuid(self):
        self._test_copy_metadata_files_with_empty_parameter(
            "",
            [
                (
                    "4d0de0aa-2658-4f21-bb09-d730b84b2b01",
                    "/home/archivematica/archivematica-sampledata/metadata.csv",
                ),
            ],
        )

    @vcr.use_cassette(
        "fixtures/vcr_cassettes/copy_metadata_files_with_empty_source_paths.yaml",
    )
    def test_copy_metadata_files_with_empty_source_paths(self):
        self._test_copy_metadata_files_with_empty_parameter(
            "f8beb140-3149-471c-861a-249e1d851c92", []
        )


class TestUtils(unittest.TestCase):
    """Test runner for utils helpers."""

    def test_package_name_from_path(self):
        """Test that package_name_from_path returns expected results."""
        test_packages = [
            {
                "current_path": "/dev/null/tar_gz_package-473a9398-0024-4804-81da-38946040c8af.tar.gz",
                "package_name": "tar_gz_package-473a9398-0024-4804-81da-38946040c8af",
                "package_name_without_uuid": "tar_gz_package",
            },
            {
                "current_path": "/dev/null/a.bz2.tricky.7z.package-473a9398-0024-4804-81da-38946040c8af.7z",
                "package_name": "a.bz2.tricky.7z.package-473a9398-0024-4804-81da-38946040c8af",
                "package_name_without_uuid": "a.bz2.tricky.7z.package",
            },
            {
                "current_path": "/dev/null/uncompressed_package-3e0b3093-23ea-4937-9e2a-1fd806bb39b9",
                "package_name": "uncompressed_package-3e0b3093-23ea-4937-9e2a-1fd806bb39b9",
                "package_name_without_uuid": "uncompressed_package",
            },
        ]
        for test_package in test_packages:
            current_path = test_package["current_path"]

            package_name_with_uuid = utils.package_name_from_path(current_path)
            assert package_name_with_uuid == test_package["package_name"]

            package_name_with_uuid = utils.package_name_from_path(
                current_path, remove_uuid_suffix=False
            )
            assert package_name_with_uuid == test_package["package_name"]

            package_name_without_uuid = utils.package_name_from_path(
                current_path, remove_uuid_suffix=True
            )
            assert (
                package_name_without_uuid == test_package["package_name_without_uuid"]
            )


if __name__ == "__main__":
    unittest.main()
