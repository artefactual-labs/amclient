import collections
import hashlib
import json
import os
import unittest
import uuid
from binascii import hexlify
from unittest import mock

import pytest
import requests

from amclient import amclient
from amclient import errors


AM_URL = "http://192.168.168.192"
SS_URL = "http://192.168.168.192:8000"
AM_USER_NAME = "test"
AM_API_KEY = "3c23b0361887ace72b9d42963d9acbdf06644673"
SS_USER_NAME = "test"
SS_API_KEY = "5de62f6f4817f903dcfac47fa5cffd44685a2cf2"
TMP_DIR = ".tmp-downloads"
TRANSFER_SOURCE_UUID = "7609101e-15b2-4f4f-a19d-7b23673ac93b"


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Fetched completed transfers successfully.",
            "results": [
                "26841c49-bed4-4db3-bf77-1bb0ac5db32c",
                "2f7bb26b-d1c7-484f-b41a-7e3f2fefa084",
            ],
        }
    ],
)
def test_completed_transfers_transfers(call_url: mock.Mock):
    """Test getting completed transfers when there are completed transfers
    to get.
    """
    completed_transfers = amclient.AMClient(
        am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
    ).completed_transfers()
    assert completed_transfers["message"] == "Fetched completed transfers successfully."
    results = completed_transfers["results"]
    assert isinstance(results, list)
    assert len(results) == 2
    for item in results:
        assert amclient.is_uuid(item)

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Fetched completed transfers successfully.",
            "results": [
                "9bc0b1c7-658f-46d4-9a6f-4a282e8a8ee5",
                "d7bd50b5-6473-4e9f-8555-8515e55d0a16",
            ],
        },
        {"removed": True},
        {"removed": True},
    ],
)
def test_close_completed_transfers_transfers(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/transfer/9bc0b1c7-658f-46d4-9a6f-4a282e8a8ee5/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/transfer/d7bd50b5-6473-4e9f-8555-8515e55d0a16/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {"message": "Fetched completed transfers successfully.", "results": []}
    ],
)
def test_completed_transfers_no_transfers(call_url: mock.Mock):
    """Test getting completed transfers when there are no completed
    transfers to get.
    """
    completed_transfers = amclient.AMClient(
        am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
    ).completed_transfers()
    assert completed_transfers["message"] == "Fetched completed transfers successfully."
    results = completed_transfers["results"]
    assert isinstance(results, list)
    assert len(results) == 0

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {"message": "Fetched completed transfers successfully.", "results": []}
    ],
)
def test_close_completed_transfers_no_transfers(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "json.return_value": {
                        "message": "API key not valid.",
                        "error": True,
                    }
                }
            )
        )
    ],
)
def test_completed_transfers_bad_key(call_url: mock.Mock):
    """Test getting completed transfers when a bad AM API key is
    provided.
    """
    completed_transfers = amclient.AMClient(
        am_api_key="bad api key", am_user_name=AM_USER_NAME, am_url=AM_URL
    ).completed_transfers()
    assert completed_transfers is errors.ERR_INVALID_RESPONSE

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": "bad api key"},
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Fetched unapproved transfers successfully.",
            "results": [
                {
                    "directory": "abc",
                    "type": "standard",
                    "uuid": "6a30faef-5f70-4aa7-8f97-7ef5458b57da",
                }
            ],
        }
    ],
)
def test_unapproved_transfers_transfers(call_url: mock.Mock):
    """Test getting unapproved transfers when there are
    unapproved transfers to get.
    """
    unapproved_transfers = amclient.AMClient(
        am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
    ).unapproved_transfers()
    assert (
        unapproved_transfers["message"] == "Fetched unapproved transfers successfully."
    )
    results = unapproved_transfers["results"]
    assert isinstance(results, list)
    assert len(results) == 1
    for unapproved_transfer in results:
        assert "type" in unapproved_transfer
        assert "uuid" in unapproved_transfer
        assert "directory" in unapproved_transfer
        assert amclient.is_uuid(unapproved_transfer["uuid"])

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/unapproved",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {"message": "Fetched unapproved transfers successfully.", "results": []}
    ],
)
def test_unapproved_transfers_no_transfers(call_url: mock.Mock):
    """Test getting unapproved transfers when there are no unapproved
    transfers to get.
    """
    unapproved_transfers = amclient.AMClient(
        am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
    ).unapproved_transfers()
    assert (
        unapproved_transfers["message"] == "Fetched unapproved transfers successfully."
    )
    results = unapproved_transfers["results"]
    assert isinstance(results, list)
    assert len(results) == 0

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/unapproved",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "directories": ["dWJ1bnR1", "dmFncmFudA=="],
            "entries": ["dWJ1bnR1", "dmFncmFudA=="],
            "properties": {
                "dWJ1bnR1": {"object count": 3, "size": 4096},
                "dmFncmFudA==": {"object count": 2103, "size": 4096},
            },
        }
    ],
)
def test_transferables(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/7609101e-15b2-4f4f-a19d-7b23673ac93b/browse/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "directories": [
                "T1BGIGZvcm1hdC1jb3JwdXM=",
                "U2FtcGxlVHJhbnNmZXJz",
                "VGVzdFRyYW5zZmVycw==",
            ],
            "entries": [
                "T1BGIGZvcm1hdC1jb3JwdXM=",
                "UkVBRE1FLm1k",
                "U2FtcGxlVHJhbnNmZXJz",
                "VGVzdFRyYW5zZmVycw==",
            ],
            "properties": {
                "T1BGIGZvcm1hdC1jb3JwdXM=": {"object count": 1499, "size": 4096},
                "U2FtcGxlVHJhbnNmZXJz": {"object count": 95, "size": 4096},
                "UkVBRE1FLm1k": {"size": 201},
                "VGVzdFRyYW5zZmVycw==": {"object count": 369, "size": 4096},
            },
        }
    ],
)
def test_transferables_path(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/7609101e-15b2-4f4f-a19d-7b23673ac93b/browse/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "path": b"dmFncmFudC9hcmNoaXZlbWF0aWNhLXNhbXBsZWRhdGE=",
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[{"directories": [], "entries": [], "properties": {}}],
)
def test_transferables_bad_path(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/7609101e-15b2-4f4f-a19d-7b23673ac93b/browse/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "path": b"dmFncmFudC9hcmNoaXZlbWF0aWNhLXNhbXBsZWRhdGF6",
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=AIP",
                "offset": 0,
                "previous": None,
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/979c/ce65/2a6f/407f/a49c/1bcf/13bd/8571/make-979cce65-2a6f-407f-a49c-1bcf13bd8571.7z",
                    "current_location": "/api/v2/location/91b917bb-57ea-4cca-8c16-f6b598713f93/",
                    "current_path": "979c/ce65/2a6f/407f/a49c/1bcf/13bd/8571/make-979cce65-2a6f-407f-a49c-1bcf13bd8571.7z",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "AIP",
                    "resource_uri": "/api/v2/file/979cce65-2a6f-407f-a49c-1bcf13bd8571/",
                    "size": 24714,
                    "status": "UPLOADED",
                    "uuid": "979cce65-2a6f-407f-a49c-1bcf13bd8571",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 1,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=AIP&limit=1&offset=0",
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/3500/aee0/08ca/40ff/8d2d/9fe9/a2c3/ae3b/itbetter-3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b.7z",
                    "current_location": "/api/v2/location/91b917bb-57ea-4cca-8c16-f6b598713f93/",
                    "current_path": "3500/aee0/08ca/40ff/8d2d/9fe9/a2c3/ae3b/itbetter-3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b.7z",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "AIP",
                    "resource_uri": "/api/v2/file/3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b/",
                    "size": 8991980,
                    "status": "UPLOADED",
                    "uuid": "3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b",
                }
            ],
        },
    ],
)
def test_aips_aips(call_url: mock.Mock):
    """Test that we can get all AIPs in the Storage Service."""
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "AIP",
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=AIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
                "offset": 0,
                "previous": None,
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/7e49afa4-116b-4650-8bbb-9341906bdb21/",
                    "size": 211240,
                    "status": "UPLOADED",
                    "uuid": "7e49afa4-116b-4650-8bbb-9341906bdb21",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 1,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=DIP&limit=1&offset=0",
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/c0e37bab-e51e-482d-a066-a277330de9a7/",
                    "size": 211400,
                    "status": "UPLOADED",
                    "uuid": "c0e37bab-e51e-482d-a066-a277330de9a7",
                }
            ],
        },
    ],
)
def test_dips_dips(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "DIP",
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 0,
                "previous": None,
                "total_count": 0,
            },
            "objects": [],
        }
    ],
)
def test_dips_no_dips(call_url: mock.Mock):
    """Test that we get no DIPs from the Storage Service if there are none."""
    dips = amclient.AMClient(
        ss_url=SS_URL, ss_user_name=SS_USER_NAME, ss_api_key=SS_API_KEY
    ).dips()
    assert isinstance(dips, list)
    assert dips == []

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "DIP",
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
                "offset": 0,
                "previous": None,
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/7e49afa4-116b-4650-8bbb-9341906bdb21/",
                    "size": 211240,
                    "status": "UPLOADED",
                    "uuid": "7e49afa4-116b-4650-8bbb-9341906bdb21",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 1,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=DIP&limit=1&offset=0",
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/c0e37bab-e51e-482d-a066-a277330de9a7/",
                    "size": 211400,
                    "status": "UPLOADED",
                    "uuid": "c0e37bab-e51e-482d-a066-a277330de9a7",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=AIP",
                "offset": 0,
                "previous": None,
                "total_count": 4,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/979c/ce65/2a6f/407f/a49c/1bcf/13bd/8571/make-979cce65-2a6f-407f-a49c-1bcf13bd8571.7z",
                    "current_location": "/api/v2/location/91b917bb-57ea-4cca-8c16-f6b598713f93/",
                    "current_path": "979c/ce65/2a6f/407f/a49c/1bcf/13bd/8571/make-979cce65-2a6f-407f-a49c-1bcf13bd8571.7z",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "AIP",
                    "resource_uri": "/api/v2/file/979cce65-2a6f-407f-a49c-1bcf13bd8571/",
                    "size": 24714,
                    "status": "UPLOADED",
                    "uuid": "979cce65-2a6f-407f-a49c-1bcf13bd8571",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=AIP&limit=1&offset=2",
                "offset": 1,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=AIP&limit=1&offset=0",
                "total_count": 4,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/3500/aee0/08ca/40ff/8d2d/9fe9/a2c3/ae3b/itbetter-3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b.7z",
                    "current_location": "/api/v2/location/91b917bb-57ea-4cca-8c16-f6b598713f93/",
                    "current_path": "3500/aee0/08ca/40ff/8d2d/9fe9/a2c3/ae3b/itbetter-3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b.7z",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "AIP",
                    "resource_uri": "/api/v2/file/3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b/",
                    "size": 8991980,
                    "status": "UPLOADED",
                    "uuid": "3500aee0-08ca-40ff-8d2d-9fe9a2c3ae3b",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&package_type=AIP&api_key={SS_API_KEY}&limit=1&offset=3",
                "offset": 2,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&package_type=AIP&api_key={SS_API_KEY}&limit=1&offset=1",
                "total_count": 4,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/99bb/20ee/69c6/43d0/acf0/c566/0203/57d2/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2.7z",
                    "current_location": "/api/v2/location/91b917bb-57ea-4cca-8c16-f6b598713f93/",
                    "current_path": "99bb/20ee/69c6/43d0/acf0/c566/0203/57d2/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2.7z",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "AIP",
                    "resource_uri": "/api/v2/file/99bb20ee-69c6-43d0-acf0-c566020357d2/",
                    "size": 24772,
                    "status": "UPLOADED",
                    "uuid": "99bb20ee-69c6-43d0-acf0-c566020357d2",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 3,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=2&package_type=AIP",
                "total_count": 4,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/721b/98b9/b894/4cfb/80ab/624e/5226/3300/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300.7z",
                    "current_location": "/api/v2/location/91b917bb-57ea-4cca-8c16-f6b598713f93/",
                    "current_path": "721b/98b9/b894/4cfb/80ab/624e/5226/3300/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300.7z",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "AIP",
                    "resource_uri": "/api/v2/file/721b98b9-b894-4cfb-80ab-624e52263300/",
                    "size": 24829,
                    "status": "UPLOADED",
                    "uuid": "721b98b9-b894-4cfb-80ab-624e52263300",
                }
            ],
        },
    ],
)
def test_aips2dips(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "DIP",
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "AIP",
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=AIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=AIP&limit=1&offset=2",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&package_type=AIP&api_key={SS_API_KEY}&limit=1&offset=3",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
                "offset": 0,
                "previous": None,
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/7e49afa4-116b-4650-8bbb-9341906bdb21/",
                    "size": 211240,
                    "status": "UPLOADED",
                    "uuid": "7e49afa4-116b-4650-8bbb-9341906bdb21",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 1,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=DIP&limit=1&offset=0",
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/c0e37bab-e51e-482d-a066-a277330de9a7/",
                    "size": 211400,
                    "status": "UPLOADED",
                    "uuid": "c0e37bab-e51e-482d-a066-a277330de9a7",
                }
            ],
        },
    ],
)
def test_aip2dips_dips(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "DIP",
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 1,
                "next": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
                "offset": 0,
                "previous": None,
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "7e49/afa4/116b/4650/8bbb/9341/906b/db21/make_dips-99bb20ee-69c6-43d0-acf0-c566020357d2",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/7e49afa4-116b-4650-8bbb-9341906bdb21/",
                    "size": 211240,
                    "status": "UPLOADED",
                    "uuid": "7e49afa4-116b-4650-8bbb-9341906bdb21",
                }
            ],
        },
        {
            "meta": {
                "limit": 1,
                "next": None,
                "offset": 1,
                "previous": f"/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=DIP&limit=1&offset=0",
                "total_count": 2,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/DIPsStore/c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "current_location": "/api/v2/location/5150d0e2-f643-404c-aab5-cf7ebcea05bf/",
                    "current_path": "c0e3/7bab/e51e/482d/a066/a277/330d/e9a7/make_dips_2-721b98b9-b894-4cfb-80ab-624e52263300",
                    "origin_pipeline": "/api/v2/pipeline/a702cea2-9666-42e4-9784-6881e3fb5f67/",
                    "package_type": "DIP",
                    "resource_uri": "/api/v2/file/c0e37bab-e51e-482d-a066-a277330de9a7/",
                    "size": 211400,
                    "status": "UPLOADED",
                    "uuid": "c0e37bab-e51e-482d-a066-a277330de9a7",
                }
            ],
        },
    ],
)
def test_aip2dips_no_dips(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "DIP",
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"http://192.168.168.192:8000/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 200,
                "headers": {},
                "iter_content.return_value": iter([b"dip"]),
            }
        ),
    ],
)
def test_download_dip_dip(requests_get: mock.Mock, tmp_path):
    """Test that we can download a DIP when there is one."""
    tmp_dir = tmp_path / "dip"
    tmp_dir.mkdir()
    dip_uuid = "c0e37bab-e51e-482d-a066-a277330de9a7"
    dip_path = amclient.AMClient(
        dip_uuid=dip_uuid,
        ss_url=SS_URL,
        ss_user_name=SS_USER_NAME,
        ss_api_key=SS_API_KEY,
        directory=tmp_dir.as_posix(),
    ).download_dip()
    assert dip_path == f"{tmp_dir}/package-c0e37bab-e51e-482d-a066-a277330de9a7.7z"
    assert os.path.isfile(dip_path)

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/c0e37bab-e51e-482d-a066-a277330de9a7/download/",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 404,
            }
        ),
    ],
)
def test_download_dip_no_dip(requests_get: mock.Mock):
    """Test that we can try to download a DIP that does not exist."""
    dip_uuid = "bad dip uuid"
    dip_path = amclient.AMClient(
        dip_uuid=dip_uuid,
        ss_url=SS_URL,
        ss_user_name=SS_USER_NAME,
        ss_api_key=SS_API_KEY,
    ).download_dip()
    assert dip_path is None

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/bad dip uuid/download/",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 200,
                "headers": requests.structures.CaseInsensitiveDict(
                    {
                        "Content-Disposition": '[attachment; filename="transfer-216dd8a6-c366-41f8-b11e-0c70814b3992.7z"]',
                    }
                ),
                "iter_content.return_value": iter([b"aip"]),
            }
        ),
    ],
)
def test_download_aip_success(requests_get: mock.Mock, tmp_path):
    """Test that we can download an AIP when there is one."""
    tmp_dir = tmp_path / "aip"
    tmp_dir.mkdir()
    aip_uuid = "216dd8a6-c366-41f8-b11e-0c70814b3992"
    transfer_name = "transfer"
    aip_path = amclient.AMClient(
        aip_uuid=aip_uuid,
        ss_url=SS_URL,
        ss_user_name=SS_USER_NAME,
        ss_api_key=SS_API_KEY,
        directory=tmp_dir.as_posix(),
    ).download_aip()
    assert aip_path == f"{tmp_dir}/{transfer_name}-{aip_uuid}.7z"
    assert os.path.isfile(aip_path)

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/216dd8a6-c366-41f8-b11e-0c70814b3992/download/",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 404,
            }
        ),
    ],
)
def test_download_aip_fail(requests_get: mock.Mock):
    """Test that we can try to download an AIP that does not exist."""
    aip_uuid = "bad-aip-uuid"
    aip_path = amclient.AMClient(
        aip_uuid=aip_uuid,
        ss_url=SS_URL,
        ss_user_name=SS_USER_NAME,
        ss_api_key=SS_API_KEY,
    ).download_aip()
    assert aip_path is None

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/bad-aip-uuid/download/",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[{"message": "Delete request created successfully.", "id": 2}],
)
def test_delete_aip_success(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/fccc77cf-2045-44ed-9ddc-b335c63d5f9a/delete_aip/",
            method="POST",
            data=json.dumps(
                {
                    "pipeline": pipeline_uuid,
                    "event_reason": "Testing that deletion request works",
                    "user_id": "1",
                    "user_email": "test@example.com",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "json.return_value": "Resource with UUID bad-aip-uuid does not exist",
                }
            )
        )
    ],
)
def test_delete_aip_fail(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/bad-aip-uuid/delete_aip/",
            method="POST",
            data=json.dumps(
                {
                    "pipeline": pipeline_uuid,
                    "event_reason": "Testing when deletion request doesn't work",
                    "user_id": "1",
                    "user_email": "test@example.com",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Fetched completed ingests successfully.",
            "results": [
                "66391111-0dba-4236-877f-b61cda71cf23",
                "88394649-3d72-491b-9742-c5e673bf80e0",
            ],
        }
    ],
)
def test_completed_ingests_ingests(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Fetched completed ingests successfully.",
            "results": [
                "2d75323c-70a0-4d5f-a8d0-762e729fc2b9",
                "57d7faff-c397-4485-9035-6eaeb5c35636",
            ],
        },
        {"removed": True},
        {"removed": True},
    ],
)
def test_close_completed_ingests_ingests(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/ingest/2d75323c-70a0-4d5f-a8d0-762e729fc2b9/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/ingest/57d7faff-c397-4485-9035-6eaeb5c35636/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {"removed": True},
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 404,
                }
            )
        ),
        {"removed": True},
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 404,
                }
            )
        ),
    ],
)
def test_hide_units(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/fdf1f7d4-7b0e-46d7-a1cc-e1851f8b92ed/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/transfer/777a9d9e-baad-f00d-8c7e-00b75773672d/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/ingest/b72afa68-9e82-410d-9235-02fa10512e14/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/ingest/777a9d9e-baad-f00d-8c7e-00b75773672d/delete/",
            method="DELETE",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[{"message": "Fetched completed ingests successfully.", "results": []}],
)
def test_completed_ingests_no_ingests(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[{"message": "Fetched completed ingests successfully.", "results": []}],
)
def test_close_completed_ingests_no_ingests(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/completed",
            method="GET",
            params={
                "username": AM_USER_NAME,
                "api_key": AM_API_KEY,
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 20,
                "next": None,
                "offset": 0,
                "previous": None,
                "total_count": 1,
            },
            "objects": [
                {
                    "description": "Archivematica on ff4c2e051a31",
                    "remote_name": "172.18.0.13",
                    "resource_uri": "/api/v2/pipeline/f914af05-c7d2-4611-b2eb-61cd3426d9d2/",
                    "uuid": "f914af05-c7d2-4611-b2eb-61cd3426d9d2",
                }
            ],
        },
    ],
)
def test_get_pipelines(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/pipeline/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 20,
                "next": None,
                "offset": 0,
                "previous": None,
                "total_count": 0,
            },
            "objects": [],
        }
    ],
)
def test_get_pipelines_none(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/pipeline/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "status": "COMPLETE",
            "name": "transfer_test_1",
            "sip_uuid": "BACKLOG",
            "microservice": "Create placement in backlog PREMIS events",
            "directory": "transfer_test_1-63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9",
            "path": "/var/archivematica/sharedDirectory/watchedDirectories/SIPCreation/completedTransfers/transfer_test_1-63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9/",
            "message": "Fetched status for 63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9 successfully.",
            "type": "transfer",
            "uuid": "63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9",
        }
    ],
)
def test_get_transfer_status(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/status/63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Cannot fetch unitTransfer with UUID 7bffc8f7-baad-f00d-8120-b1c51c2ab5db",
            "type": "transfer",
            "error": True,
        }
    ],
)
def test_get_transfer_status_invalid_uuid(call_url: mock.Mock):
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
        "Cannot fetch unitTransfer with UUID 7bffc8f7-" "baad-f00d-8120-b1c51c2ab5db"
    )
    assert message_type == "transfer"

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/status/7bffc8f7-baad-f00d-8120-b1c51c2ab5db/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "status": "COMPLETE",
            "name": "five",
            "microservice": "Remove the processing directory",
            "directory": "five-23129471-09e3-467e-88b6-eb4714afb5ac",
            "path": "/var/archivematica/sharedDirectory/currentlyProcessing/five-23129471-09e3-467e-88b6-eb4714afb5ac/",
            "message": "Fetched status for 23129471-09e3-467e-88b6-eb4714afb5ac successfully.",
            "type": "SIP",
            "uuid": "23129471-09e3-467e-88b6-eb4714afb5ac",
        }
    ],
)
def test_get_ingest_status(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/status/23129471-09e3-467e-88b6-eb4714afb5ac/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 400,
                }
            )
        ),
    ],
)
def test_get_ingest_status_invalid_uuid(call_url: mock.Mock):
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/status/63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        "<processingMCP><preconfiguredChoices></preconfiguredChoices></processingMCP>"
    ],
)
def test_get_processing_config(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/processing-configuration/default",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=False,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 404,
                }
            )
        ),
    ],
)
def test_get_non_existing_processing_config(call_url: mock.Mock):
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/processing-configuration/badf00d",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=False,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "message": "Approval successful.",
            "uuid": "5ad38ce3-27e5-4211-a0b5-eb70f13d28fa",
        }
    ],
)
def test_approve_transfer(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/approve/",
            method="POST",
            data={"type": "standard", "directory": b"approve_1"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 500,
                }
            )
        ),
    ],
)
def test_approve_non_existing_transfer(call_url: mock.Mock):
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/transfer/approve/",
            method="POST",
            data={"type": "standard", "directory": b"approve_2"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "error": False,
            "message": "Package df8e0c68-3bda-4d1d-8493-789f7dec47f5 sent to pipeline Archivematica on 4e2f66a7a29f (65aaac5d-b4fd-478e-967b-6cdfee02f2c5) for re-ingest",
            "reingest_uuid": "9dac7039-b0d8-4185-b27e-af008a9687ac",
            "status_code": 202,
        },
    ],
)
def test_reingest_aip(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/df8e0c68-3bda-4d1d-8493-789f7dec47f5/reingest/",
            method="POST",
            data=json.dumps(
                {
                    "pipeline": pipeline_uuid,
                    "reingest_type": "standard",
                    "processing_config": "default",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 404,
                }
            )
        ),
    ],
)
def test_reingest_non_aip(call_url: mock.Mock):
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/bb033eff-131e-48d5-980f-c4edab0cb038/reingest/",
            method="POST",
            data=json.dumps(
                {
                    "pipeline": pipeline_uuid,
                    "reingest_type": "standard",
                    "processing_config": "default",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "current_full_path": "/var/archivematica/sharedDirectory/www/AIPsStore/2312/9471/09e3/467e/88b6/eb47/14af/b5ac/five-23129471-09e3-467e-88b6-eb4714afb5ac.7z",
            "current_location": "/api/v2/location/b69754bb-3367-44f0-a00c-8eca0c0b53dd/",
            "current_path": "2312/9471/09e3/467e/88b6/eb47/14af/b5ac/five-23129471-09e3-467e-88b6-eb4714afb5ac.7z",
            "encrypted": False,
            "misc_attributes": {"reingest_pipeline": None},
            "origin_pipeline": "/api/v2/pipeline/cc3bf7dd-ab62-4e19-927e-6a5e196294e2/",
            "package_type": "AIP",
            "related_packages": [],
            "replicas": [],
            "replicated_package": None,
            "resource_uri": "/api/v2/file/23129471-09e3-467e-88b6-eb4714afb5ac/",
            "size": 19606,
            "status": "UPLOADED",
            "uuid": "23129471-09e3-467e-88b6-eb4714afb5ac",
        }
    ],
)
def test_get_package_details(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/23129471-09e3-467e-88b6-eb4714afb5ac",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 404,
                }
            )
        ),
    ],
)
def test_get_package_details_invalid_uuid(call_url: mock.Mock):
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/23129471-baad-f00d-88b6-eb4714afb5ac",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 20,
                "next": None,
                "offset": 0,
                "previous": None,
                "total_count": 5,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/5843/53f3/c402/4ff5/a00c/59d0/e133/4683/deleted_1-584353f3-c402-4ff5-a00c-59d0e1334683.7z",
                    "current_location": "/api/v2/location/022713c0-f298-4d74-90fb-eb17da38d44f/",
                    "current_path": "5843/53f3/c402/4ff5/a00c/59d0/e133/4683/deleted_1-584353f3-c402-4ff5-a00c-59d0e1334683.7z",
                    "encrypted": False,
                    "misc_attributes": {"reingest_pipeline": None},
                    "origin_pipeline": "/api/v2/pipeline/79120a48-974a-46eb-ac01-eee496e0f57f/",
                    "package_type": "AIP",
                    "related_packages": [],
                    "replicas": [],
                    "replicated_package": None,
                    "resource_uri": "/api/v2/file/584353f3-c402-4ff5-a00c-59d0e1334683/",
                    "size": 13284,
                    "status": "DELETED",
                    "uuid": "584353f3-c402-4ff5-a00c-59d0e1334683",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/6f54/7b25/aea0/4161/9f68/316f/c246/5fd9/deleted_2-6f547b25-aea0-4161-9f68-316fc2465fd9.7z",
                    "current_location": "/api/v2/location/022713c0-f298-4d74-90fb-eb17da38d44f/",
                    "current_path": "6f54/7b25/aea0/4161/9f68/316f/c246/5fd9/deleted_2-6f547b25-aea0-4161-9f68-316fc2465fd9.7z",
                    "encrypted": False,
                    "misc_attributes": {"reingest_pipeline": None},
                    "origin_pipeline": "/api/v2/pipeline/79120a48-974a-46eb-ac01-eee496e0f57f/",
                    "package_type": "AIP",
                    "related_packages": [],
                    "replicas": [],
                    "replicated_package": None,
                    "resource_uri": "/api/v2/file/6f547b25-aea0-4161-9f68-316fc2465fd9/",
                    "size": 13277,
                    "status": "DELETED",
                    "uuid": "6f547b25-aea0-4161-9f68-316fc2465fd9",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/6d32/a85f/6715/43af/947c/83c9/d7f0/deac/transfer_1-6d32a85f-6715-43af-947c-83c9d7f0deac.7z",
                    "current_location": "/api/v2/location/022713c0-f298-4d74-90fb-eb17da38d44f/",
                    "current_path": "6d32/a85f/6715/43af/947c/83c9/d7f0/deac/transfer_1-6d32a85f-6715-43af-947c-83c9d7f0deac.7z",
                    "encrypted": False,
                    "misc_attributes": {},
                    "origin_pipeline": "/api/v2/pipeline/79120a48-974a-46eb-ac01-eee496e0f57f/",
                    "package_type": "AIP",
                    "related_packages": [],
                    "replicas": [],
                    "replicated_package": None,
                    "resource_uri": "/api/v2/file/6d32a85f-6715-43af-947c-83c9d7f0deac/",
                    "size": 13230,
                    "status": "UPLOADED",
                    "uuid": "6d32a85f-6715-43af-947c-83c9d7f0deac",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/6f19/8696/e3b6/4f45/8ab3/b4cd/4afd/921a/transfer_2-6f198696-e3b6-4f45-8ab3-b4cd4afd921a.7z",
                    "current_location": "/api/v2/location/022713c0-f298-4d74-90fb-eb17da38d44f/",
                    "current_path": "6f19/8696/e3b6/4f45/8ab3/b4cd/4afd/921a/transfer_2-6f198696-e3b6-4f45-8ab3-b4cd4afd921a.7z",
                    "encrypted": False,
                    "misc_attributes": {},
                    "origin_pipeline": "/api/v2/pipeline/79120a48-974a-46eb-ac01-eee496e0f57f/",
                    "package_type": "AIP",
                    "related_packages": [],
                    "replicas": [],
                    "replicated_package": None,
                    "resource_uri": "/api/v2/file/6f198696-e3b6-4f45-8ab3-b4cd4afd921a/",
                    "size": 13269,
                    "status": "UPLOADED",
                    "uuid": "6f198696-e3b6-4f45-8ab3-b4cd4afd921a",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/9c5e/dcdc/3e3f/499d/a016/a43b/9db8/75b1/transfer_3-9c5edcdc-3e3f-499d-a016-a43b9db875b1.7z",
                    "current_location": "/api/v2/location/022713c0-f298-4d74-90fb-eb17da38d44f/",
                    "current_path": "9c5e/dcdc/3e3f/499d/a016/a43b/9db8/75b1/transfer_3-9c5edcdc-3e3f-499d-a016-a43b9db875b1.7z",
                    "encrypted": False,
                    "misc_attributes": {},
                    "origin_pipeline": "/api/v2/pipeline/79120a48-974a-46eb-ac01-eee496e0f57f/",
                    "package_type": "AIP",
                    "related_packages": [],
                    "replicas": [],
                    "replicated_package": None,
                    "resource_uri": "/api/v2/file/9c5edcdc-3e3f-499d-a016-a43b9db875b1/",
                    "size": 13236,
                    "status": "UPLOADED",
                    "uuid": "9c5edcdc-3e3f-499d-a016-a43b9db875b1",
                },
            ],
        }
    ],
)
def test_get_all_compressed_aips(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "package_type": "AIP",
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 20,
                "next": None,
                "offset": 0,
                "previous": None,
                "total_count": 7,
            },
            "objects": [
                {
                    "description": "",
                    "enabled": True,
                    "path": "/home",
                    "pipeline": [
                        "/api/v2/pipeline/1ffc9650-4862-4e53-a4f1-9c7e2a26ab72/"
                    ],
                    "purpose": "TS",
                    "quota": None,
                    "relative_path": "home",
                    "resource_uri": "/api/v2/location/d1184f7f-d755-4c8d-831a-a3793b88f760/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "d1184f7f-d755-4c8d-831a-a3793b88f760",
                },
                {
                    "description": "Store AIP in standard Archivematica Directory",
                    "enabled": True,
                    "path": "/var/archivematica/sharedDirectory/www/AIPsStore",
                    "pipeline": [
                        "/api/v2/pipeline/1ffc9650-4862-4e53-a4f1-9c7e2a26ab72/"
                    ],
                    "purpose": "AS",
                    "quota": None,
                    "relative_path": "var/archivematica/sharedDirectory/www/AIPsStore",
                    "resource_uri": "/api/v2/location/471ff191-2c03-441d-b1d6-0c39d27a6b66/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "471ff191-2c03-441d-b1d6-0c39d27a6b66",
                },
                {
                    "description": "Store DIP in standard Archivematica Directory",
                    "enabled": True,
                    "path": "/var/archivematica/sharedDirectory/www/DIPsStore",
                    "pipeline": [
                        "/api/v2/pipeline/1ffc9650-4862-4e53-a4f1-9c7e2a26ab72/"
                    ],
                    "purpose": "DS",
                    "quota": None,
                    "relative_path": "var/archivematica/sharedDirectory/www/DIPsStore",
                    "resource_uri": "/api/v2/location/b7783482-a2ca-4dc8-9f3e-6305c7569268/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "b7783482-a2ca-4dc8-9f3e-6305c7569268",
                },
                {
                    "description": "Default transfer backlog",
                    "enabled": True,
                    "path": "/var/archivematica/sharedDirectory/www/AIPsStore/transferBacklog",
                    "pipeline": [
                        "/api/v2/pipeline/1ffc9650-4862-4e53-a4f1-9c7e2a26ab72/"
                    ],
                    "purpose": "BL",
                    "quota": None,
                    "relative_path": "var/archivematica/sharedDirectory/www/AIPsStore/transferBacklog",
                    "resource_uri": "/api/v2/location/77dd226a-39b2-4217-b2a4-e17dad1beaae/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "77dd226a-39b2-4217-b2a4-e17dad1beaae",
                },
                {
                    "description": "For storage service internal usage.",
                    "enabled": True,
                    "path": "/var/archivematica/storage_service",
                    "pipeline": [],
                    "purpose": "SS",
                    "quota": None,
                    "relative_path": "var/archivematica/storage_service",
                    "resource_uri": "/api/v2/location/e8f346b7-0090-44b5-8b31-bff7f9d74e98/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "e8f346b7-0090-44b5-8b31-bff7f9d74e98",
                },
                {
                    "description": "Default AIP recovery",
                    "enabled": True,
                    "path": "/var/archivematica/storage_service/recover",
                    "pipeline": [
                        "/api/v2/pipeline/1ffc9650-4862-4e53-a4f1-9c7e2a26ab72/"
                    ],
                    "purpose": "AR",
                    "quota": None,
                    "relative_path": "var/archivematica/storage_service/recover",
                    "resource_uri": "/api/v2/location/52bea1a4-0853-4082-8a63-3540b79d1772/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "52bea1a4-0853-4082-8a63-3540b79d1772",
                },
                {
                    "description": None,
                    "enabled": True,
                    "path": "/var/archivematica/sharedDirectory",
                    "pipeline": [
                        "/api/v2/pipeline/1ffc9650-4862-4e53-a4f1-9c7e2a26ab72/"
                    ],
                    "purpose": "CP",
                    "quota": None,
                    "relative_path": "var/archivematica/sharedDirectory/",
                    "resource_uri": "/api/v2/location/4fdc5235-40cd-4b73-b63a-8df54e037061/",
                    "space": "/api/v2/space/f18ad8dd-9082-4f5c-bc67-b976e370fa90/",
                    "used": "0",
                    "uuid": "4fdc5235-40cd-4b73-b63a-8df54e037061",
                },
            ],
        }
    ],
)
def test_get_default_storage_locations(call_url: mock.Mock):
    """Test that amclient can successfully retrieve Archivematica's default
    storage locations.
    """
    response = amclient.AMClient(
        ss_api_key=SS_API_KEY, ss_user_name=SS_USER_NAME, ss_url=SS_URL
    ).list_storage_locations()
    count = response.get("meta").get("total_count")
    if not count:
        raise AssertionError("Cannot retrieve storage location count")
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/",
            method="GET",
            params="{}",
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {"id": "8e6259a0-34c8-4514-be3c-18dc0d42ce1c"},
        {"id": "8b15874d-d411-4bb7-adb3-eba300a3ef1e"},
        {"id": "8b15874d-d411-4bb7-adb3-eba300a3ef1e"},
    ],
)
def test_create_package_endpoint(call_url: mock.Mock):
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
        raise AssertionError()
    # Provide a test for an absolute path, over relative above.
    path = (
        "/home/archivematica/archivematica-sampledata/SampleTransfers/" "DemoTransfer"
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
        raise AssertionError()
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
        raise AssertionError()

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/v2beta/package/",
            method="POST",
            data=json.dumps(
                {
                    "name": "amclient-transfer",
                    "path": "ZDExODRmN2YtZDc1NS00YzhkLTgzMWEtYTM3OTNiODhmNzYwOi9hcmNoaXZlbWF0aWNhL2FyY2hpdmVtYXRpY2Etc2FtcGxlZGF0YS9TYW1wbGVUcmFuc2ZlcnMvRGVtb1RyYW5zZmVy",
                    "type": "standard",
                    "processing_config": "automated",
                }
            ),
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/v2beta/package/",
            method="POST",
            data=json.dumps(
                {
                    "name": "amclient-transfer",
                    "path": "L2hvbWUvYXJjaGl2ZW1hdGljYS9hcmNoaXZlbWF0aWNhLXNhbXBsZWRhdGEvU2FtcGxlVHJhbnNmZXJzL0RlbW9UcmFuc2Zlcg==",
                    "type": "standard",
                    "processing_config": "automated",
                }
            ),
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/v2beta/package/",
            method="POST",
            data=json.dumps(
                {
                    "name": "amclient-transfer",
                    "path": "ZDExODRmN2YtZDc1NS00YzhkLTgzMWEtYTM3OTNiODhmNzYwOi9hcmNoaXZlbWF0aWNhL2FyY2hpdmVtYXRpY2Etc2FtcGxlZGF0YS9TYW1wbGVUcmFuc2ZlcnMvQmFnVHJhbnNmZXI=",
                    "type": "unzipped bag",
                    "processing_config": "automated",
                }
            ),
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 200,
                "headers": requests.structures.CaseInsensitiveDict(
                    {
                        "Content-Disposition": 'attachment; filename="bird.mp3"',
                        "Content-Length": "3",
                    }
                ),
                "iter_content.return_value": iter([b"aip"]),
            }
        ),
    ],
)
def test_extract_individual_file(requests_get: mock.Mock, tmp_path):
    """Test the result of downloading an individual file from a package in
    the storage service.
    """
    tmp_dir = tmp_path / "aip"
    tmp_dir.mkdir()
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
        directory=tmp_dir.as_posix(),
    ).extract_file()
    file_ = os.path.join(tmp_dir, filename)
    assert os.path.isfile(file_)
    assert os.path.getsize(file_) == int(response.get("Content-Length", 0))
    assert filename_to_test in response.get("Content-Disposition", "")

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/2ad1bf0d-23fa-44e0-a128-9feadfe22c42/extract_file/?relative_path_to_file=amclient-transfer_1-2ad1bf0d-23fa-44e0-a128-9feadfe22c42/data/objects/bird.mp3",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 200,
                "headers": requests.structures.CaseInsensitiveDict(
                    {
                        "Content-Disposition": 'attachment; filename="bird.mp3"',
                        "Content-Length": "3",
                    }
                ),
                "iter_content.return_value": iter([b"aip"]),
            }
        ),
    ],
)
def test_extract_and_stream_individual_file(requests_get: mock.Mock, tmp_path):
    """Test the result of downloading an individual file from a package in
    the storage service.
    """
    tmp_dir = tmp_path / "aip"
    tmp_dir.mkdir()
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
        directory=tmp_dir.as_posix(),
        stream=True,
    ).extract_file()
    # We have a stream, check we have an iterator and some content.
    assert hexlify(next(response.iter_content(chunk_size=14))) == b"616970"
    assert response.headers.get("Content-Length") == "3"
    assert filename_to_test in response.headers.get("Content-Disposition", "")

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/2ad1bf0d-23fa-44e0-a128-9feadfe22c42/extract_file/?relative_path_to_file=amclient-transfer_1-2ad1bf0d-23fa-44e0-a128-9feadfe22c42/data/objects/bird.mp3",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 200,
                "headers": requests.structures.CaseInsensitiveDict(
                    {
                        "Content-Disposition": 'attachment; filename="bird.mp3"',
                    }
                ),
                "iter_content.return_value": iter(["aip"]),
            }
        ),
    ],
)
def test_extract_and_stream_individual_file_cli(
    requests_get: mock.Mock, tmp_path, capsys
):
    """Test the result of downloading an individual file from a package in
    the storage service. Specifically if via the CLI.
    """
    tmp_dir = tmp_path / "aip"
    tmp_dir.mkdir()
    filename_to_test = "bird.mp3"
    package_uuid = "2ad1bf0d-23fa-44e0-a128-9feadfe22c42"
    path = "amclient-transfer_1-{}/data/objects/{}".format(
        package_uuid, filename_to_test
    )
    amclient.AMClient(
        ss_api_key=SS_API_KEY,
        ss_user_name=SS_USER_NAME,
        ss_url=SS_URL,
        package_uuid=package_uuid,
        relative_path=path,
        directory=tmp_dir.as_posix(),
        stream=True,
    ).extract_file_stream()
    captured = capsys.readouterr()
    assert "aip" in captured.out
    assert len(captured.out) == 3
    # We are working with archival objects, lets make sure the return
    # is as robust as possible, i.e. no stray bytes.
    assert (
        hashlib.md5(captured.out.encode()).hexdigest()
        == "4f08f51bf4a8332250797567af889ece"
    )

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/2ad1bf0d-23fa-44e0-a128-9feadfe22c42/extract_file/?relative_path_to_file=amclient-transfer_1-2ad1bf0d-23fa-44e0-a128-9feadfe22c42/data/objects/bird.mp3",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "meta": {
                "limit": 20,
                "next": None,
                "offset": 0,
                "previous": None,
                "total_count": 1,
            },
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/www/secondAIPsStore/64f4/cb73/60bc/49f2/ab75/d83c/9365/b7d3/mkv-characterization-64f4cb73-60bc-49f2-ab75-d83c9365b7d3.7z",
                    "current_location": "/api/v2/location/52dee701-e8fb-4aa9-92b3-b86ab8c24478/",
                    "current_path": "64f4/cb73/60bc/49f2/ab75/d83c/9365/b7d3/mkv-characterization-64f4cb73-60bc-49f2-ab75-d83c9365b7d3.7z",
                    "encrypted": False,
                    "misc_attributes": {},
                    "origin_pipeline": "/api/v2/pipeline/6ba850ec-ec7f-4a53-9a8a-f3598aa39b93/",
                    "package_type": "AIP",
                    "related_packages": [],
                    "replicas": [],
                    "replicated_package": None,
                    "resource_uri": "/api/v2/file/64f4cb73-60bc-49f2-ab75-d83c9365b7d3/",
                    "size": 1065067,
                    "status": "UPLOADED",
                    "uuid": "64f4cb73-60bc-49f2-ab75-d83c9365b7d3",
                }
            ],
        }
    ],
)
@mock.patch(
    "requests.get",
    side_effect=[
        mock.Mock(
            **{
                "status_code": 200,
                "headers": requests.structures.CaseInsensitiveDict(
                    {
                        "Content-Disposition": 'attachment; filename="METS.64f4cb73-60bc-49f2-ab75-d83c9365b7d3.xml"',
                    }
                ),
                "iter_content.return_value": iter([b"mets"]),
            }
        ),
    ],
)
def test_extract_aip_mets_file(requests_get: mock.Mock, call_url: mock.Mock, tmp_path):
    """Test the result of downloading an individual file from a package in
    the storage service.
    """
    tmp_dir = tmp_path / "aip"
    tmp_dir.mkdir()
    package_uuid = "64f4cb73-60bc-49f2-ab75-d83c9365b7d3"
    am = amclient.AMClient(
        ss_api_key=SS_API_KEY,
        ss_user_name=SS_USER_NAME,
        ss_url=SS_URL,
        directory=tmp_dir.as_posix(),
    )
    am.aip_uuid = package_uuid
    response = am.extract_aip_mets_file()
    mets_filename = f"METS.{package_uuid}.xml"
    file_ = os.path.join(tmp_dir, mets_filename)
    assert os.path.isfile(file_)
    assert os.path.getsize(file_) == 4
    assert mets_filename in response.get("Content-Disposition", "")

    assert requests_get.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/64f4cb73-60bc-49f2-ab75-d83c9365b7d3/extract_file/?relative_path_to_file=mkv-characterization-64f4cb73-60bc-49f2-ab75-d83c9365b7d3/data/METS.64f4cb73-60bc-49f2-ab75-d83c9365b7d3.xml",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/file/",
            method="GET",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
                "uuid": "64f4cb73-60bc-49f2-ab75-d83c9365b7d3",
            },
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        [
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "2bcb3e40-5b66-432c-a25d-93e869827a83", "exit_code": 0},
                    {"uuid": "443b92a3-470b-4ec2-8c57-dea9006277ba", "exit_code": 0},
                    {"uuid": "5796dd25-1f43-4f4c-a3ea-166ff4bdd2ad", "exit_code": 0},
                    {"uuid": "70e71773-bbd3-4c89-8ff6-265aa991b715", "exit_code": 0},
                    {"uuid": "9ef0ec8b-027c-4743-9054-51979770b7b0", "exit_code": 0},
                    {"uuid": "bf5c2a95-511a-4a31-9718-03b06f1ed2d7", "exit_code": 0},
                    {"uuid": "cad99f5c-f9f9-4695-9479-71781a0a262c", "exit_code": 0},
                    {"uuid": "d1397901-9b63-4430-94ee-4fb9a3637620", "exit_code": 0},
                    {"uuid": "e49584a3-6b38-4eec-b5f8-28d8a512f594", "exit_code": 0},
                    {"uuid": "e9064fd3-93a1-4a4f-848b-37b120b1cebf", "exit_code": 0},
                    {"uuid": "f973f03f-9653-4165-8af5-b3f66def59f3", "exit_code": 0},
                ],
                "microservice": "Scan for viruses",
                "uuid": "01233bfd-5405-4232-a098-9e1234dd7702",
                "link_uuid": "1c2550f1-3fc0-45d8-8bc4-4c06d720283b",
                "name": "Scan for viruses",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Identify file format",
                "uuid": "02d07c50-e9cd-4378-8483-accfa405d0fe",
                "link_uuid": "c3269a0a-91db-44e8-96d0-9c748cf80177",
                "name": "Determine which files to identify",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "62843ffb-1920-41a1-b20e-f2e0a1c155cb", "exit_code": 0}
                ],
                "microservice": "Verify transfer compliance",
                "uuid": "0d0b3070-0b13-4d0e-9db0-2151c0181f22",
                "link_uuid": "bda96b35-48c7-44fc-9c9e-d7c5a05016c1",
                "name": "Check if file or folder",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "531477db-3a44-452b-9123-c690453a1408", "exit_code": 0}
                ],
                "microservice": "Complete transfer",
                "uuid": "0f6af028-a678-4f2c-985c-ef52ed463c2f",
                "link_uuid": "d27fd07e-d3ed-4767-96a5-44a2251c6d0a",
                "name": "Move to SIP creation directory for completed transfers",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Validation",
                "uuid": "11e5d093-1810-490e-8b18-68559f7a16d4",
                "link_uuid": "70fc7040-d4fb-4d19-a0e6-792387ca1006",
                "name": "Perform policy checks on originals?",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Identify DSpace files",
                "uuid": "15a07937-14ac-48d7-8972-ab3701b1cccc",
                "link_uuid": "d0dfbd93-d2d0-44db-9945-94fd8de8a1d4",
                "name": "Identify DSpace text files",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "a866425f-7deb-40e5-8324-b6b469beaac6", "exit_code": 0}
                ],
                "microservice": "Verify transfer compliance",
                "uuid": "15aa4ca7-5d04-4c5b-8d78-b398d5cfc732",
                "link_uuid": "26bf24c9-9139-4923-bf99-aa8648b1692b",
                "name": "Set transfer type: DSpace",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "3e722b0c-455a-41f4-8aca-de2e21894531", "exit_code": 0}
                ],
                "microservice": "Verify transfer compliance",
                "uuid": "162484b8-65cc-4e0b-9b2d-e02e7a52e2c4",
                "link_uuid": "87e7659c-d5de-4541-a09c-6deec966a0c0",
                "name": "Verify mets_structmap.xml compliance",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "9a0ff593-c803-40d6-b5b9-251340f6088b", "exit_code": 0}
                ],
                "microservice": "Generate METS.xml document",
                "uuid": "19dd3210-f1ca-45c3-baf9-a454a5a39653",
                "link_uuid": "307edcde-ad10-401c-92c4-652917c993ed",
                "name": "Generate METS.xml document",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "abe7fee7-cd52-42ed-a2f7-f1518b14f87a", "exit_code": 0}
                ],
                "microservice": "Characterize and extract metadata",
                "uuid": "1c4e9667-b570-403c-ad4f-a5b6494fd826",
                "link_uuid": "1b1a4565-b501-407b-b40f-2f20889423f1",
                "name": "Load labels from metadata/file_labels.csv",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "fc5b29ae-9281-4c5d-a905-eec5ce991aa9", "exit_code": 0}
                ],
                "microservice": "Generate transfer structure report",
                "uuid": "1c6b9fe8-ee7a-4916-af5f-fc8d227712aa",
                "link_uuid": "4efe00da-6ed0-45dd-89ca-421b78c4b6be",
                "name": "Save directory tree",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "90c04556-a4dd-41b2-ab16-4d8233f4df36", "exit_code": 0}
                ],
                "microservice": "Complete transfer",
                "uuid": "251ba103-fd8a-47c8-9a41-7c3da15dc92a",
                "link_uuid": "675acd22-828d-4949-adc7-1888240f5e3d",
                "name": "Parse external METS",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "e0d5ef2b-52e7-46d4-a24d-f7ff54f544cd", "exit_code": 0}
                ],
                "microservice": "Quarantine",
                "uuid": "27568f5d-9e21-4e71-bfbe-8162a5fbfbbc",
                "link_uuid": "39e58573-2dbc-4939-bce0-96b2f55dae28",
                "name": "Move to workFlowDecisions-quarantineSIP directory",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Generate transfer structure report",
                "uuid": "2987ed8b-dafc-4db9-9847-2c7e9e301528",
                "link_uuid": "56eebd45-5600-4768-a8c2-ec0114555a3d",
                "name": "Generate transfer structure report",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "120f8c42-4dbe-4165-9181-b7fcd871c1b0", "exit_code": 1}
                ],
                "microservice": "Extract packages",
                "uuid": "30474e75-6c52-46e3-8934-1855e25dbc56",
                "link_uuid": "b944ec7f-7f99-491f-986d-58914c9bb4fa",
                "name": "Determine if transfer contains packages",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "22366ae0-ca7c-4914-ae24-81a285e701ef", "exit_code": 0},
                    {"uuid": "37df5d95-45c4-4e70-8e16-d03d9386fb3d", "exit_code": 0},
                    {"uuid": "67b4bf95-0974-4d3a-b74d-5baac6d3a826", "exit_code": 0},
                    {"uuid": "7ea07f33-9964-4198-a8b5-719d5acee646", "exit_code": 0},
                    {"uuid": "893b04ab-ed6b-4f05-b59c-ec80b7337dff", "exit_code": 0},
                    {"uuid": "ad494036-d372-4c6b-b411-87f6f521e4c4", "exit_code": 0},
                    {"uuid": "b794380d-e357-4ed5-ac0c-06f255ef4d34", "exit_code": 0},
                    {"uuid": "d573fcc9-ae91-4070-9f63-1bdd12c888e4", "exit_code": 0},
                    {"uuid": "d63bba14-1f9f-40f8-921d-82feb07f4210", "exit_code": 0},
                    {"uuid": "fbbd9a85-394a-43ec-9915-6b7bbed88ea0", "exit_code": 0},
                ],
                "microservice": "Validation",
                "uuid": "37f35256-45ed-4120-a38d-b0a5a1dfbfe0",
                "link_uuid": "a536828c-be65-4088-80bd-eb511a0a063d",
                "name": "Validate formats",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Quarantine",
                "uuid": "3bc1c1e1-86a0-4cad-9cd9-4b574080dffe",
                "link_uuid": "a6e97805-a420-41af-b708-2a56de5b47a6",
                "name": "Designate to process as a DSpace transfer",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Include default Transfer processingMCP.xml",
                "uuid": "3d022b67-ba30-4c12-88f4-8f0887054683",
                "link_uuid": "d6f6f5db-4cc2-4652-9283-9ec6a6d181e5",
                "name": "Assign UUIDs to directories?",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "70a3147e-ea33-4290-86f5-c2fc663b1487", "exit_code": 0}
                ],
                "microservice": "Include default Transfer processingMCP.xml",
                "uuid": "438f13bc-8f1b-4c51-98c3-accc3e457db5",
                "link_uuid": "b08ad32b-f94f-4c2a-9fb0-9ef9328718dd",
                "name": "Assign UUIDs to directories",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "9260102c-bf06-4577-b3f0-d656f2ae649e", "exit_code": 0}
                ],
                "microservice": "Verify transfer checksum",
                "uuid": "45227afe-9ad5-4d70-ab4e-fc24fbbdb3f2",
                "link_uuid": "5e4bd4e8-d158-4c2a-be89-51e3e9bd4a06",
                "name": "Verify metadata directory checksums",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "7bc27af8-5806-4115-8f8f-49fc7ef92183", "exit_code": 0}
                ],
                "microservice": "Create SIP from Transfer",
                "uuid": "485a7c08-1fad-4e32-821b-669e80776dd2",
                "link_uuid": "8f639582-8881-4a8b-8574-d2f86dc4db3d",
                "name": "Move to processing directory",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Examine contents",
                "uuid": "54205b52-2572-4a88-b276-2f25cd0c77ab",
                "link_uuid": "accea2bf-ba74-4a3a-bb97-614775c74459",
                "name": "Examine contents?",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "81d80780-d4bf-4f70-94c4-3de13c9d7d3e", "exit_code": 0}
                ],
                "microservice": "Clean up names",
                "uuid": "5d582d29-9741-47d7-ad76-2aec612c410f",
                "link_uuid": "2584b25c-8d98-44b7-beca-2b3ea2ea2505",
                "name": "Sanitize object's file and directory names",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Quarantine",
                "uuid": "6865acde-58af-4b6e-840e-53ea90c38889",
                "link_uuid": "55de1490-f3a0-4e1e-a25b-38b75f4f05e3",
                "name": "Find type to process as",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "e523a958-388a-4743-b650-709b48b27052", "exit_code": 0}
                ],
                "microservice": "Extract packages",
                "uuid": "6a09e366-f8d1-4fdb-b6cd-2f4f3343dceb",
                "link_uuid": "cc16178b-b632-4624-9091-822dd802a2c6",
                "name": "Move to extract packages",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "bdb3310b-0d79-4a7d-a7be-6b84841f6a95", "exit_code": 0}
                ],
                "microservice": "Complete transfer",
                "uuid": "6c5bf57d-028c-4107-b6c3-2da4117f8be3",
                "link_uuid": "db99ab43-04d7-44ab-89ec-e09d7bbdc39d",
                "name": "Create transfer metadata XML",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "ea3ff112-b067-42ff-bada-cdb17f6e1ad1", "exit_code": 0}
                ],
                "microservice": "Generate transfer structure report",
                "uuid": "7314ece7-ef5d-40fb-9225-13e4f34ae2db",
                "link_uuid": "559d9b14-05bf-4136-918a-de74a821b759",
                "name": "Move to generate transfer tree",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "451f20e0-39c4-4f6a-9ff5-9d52b668caab", "exit_code": 0}
                ],
                "microservice": "Verify transfer compliance",
                "uuid": "74266c67-bf4e-456f-abb8-f168b1c4f38c",
                "link_uuid": "aa9ba088-0b1e-4962-a9d7-79d7a0cbea2d",
                "name": "Attempt restructure for compliance",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "6c45dd0c-dfb3-4c80-b99f-6bfc4921ab63", "exit_code": 0}
                ],
                "microservice": "Include default Transfer processingMCP.xml",
                "uuid": "84a78da4-5488-4bb7-b5dd-e145cf2a71af",
                "link_uuid": "209400c1-5619-4acc-b091-b9d9c8fbb1c0",
                "name": "Include default Transfer processingMCP.xml",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Quarantine",
                "uuid": "87d5859f-6e58-403f-bde8-f622d0f88d61",
                "link_uuid": "05f99ffd-abf2-4f5a-9ec8-f80a59967b89",
                "name": "Workflow decision - send transfer to quarantine",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "2b7ed475-4b56-45ff-9579-8a11dd79ba09", "exit_code": 0}
                ],
                "microservice": "Identify file format",
                "uuid": "8d76118f-a78c-485d-8a1c-67ee283b6155",
                "link_uuid": "d1b27e9e-73c8-4954-832c-36bd1e00c802",
                "name": "Move to select file ID tool",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Examine contents",
                "uuid": "8e4346b7-61a5-4348-a2b2-dafda5cb28a9",
                "link_uuid": "192315ea-a1bf-44cf-8cb4-0b3edd1522a6",
                "name": "Check for specialized processing",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "560befa7-f850-48ff-9dfd-a59d90889de5", "exit_code": 0}
                ],
                "microservice": "Include default Transfer processingMCP.xml",
                "uuid": "90d5f202-76ef-405e-829c-809a6c44112c",
                "link_uuid": "6bd4d385-c490-4c42-a195-dace8697891c",
                "name": "Rename with transfer UUID",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "0e6c5024-3d40-40d5-97d1-07afa03c0dfc", "exit_code": 0}
                ],
                "microservice": "Characterize and extract metadata",
                "uuid": "97c9b723-40f2-4517-8bb0-984eb0aacaa5",
                "link_uuid": "f8ef02c4-f585-4b0d-9b6f-3cef6fbe527f",
                "name": "Store file modification dates",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "e0e5e289-ac5e-4673-a502-b3bc1fbf1a8f", "exit_code": 179}
                ],
                "microservice": "Create SIP from Transfer",
                "uuid": "9a73a9b9-5371-4364-8daa-d7dffc6716a6",
                "link_uuid": "032cdc54-0b9b-4caf-86e8-10d63efbaec0",
                "name": "Check transfer directory for objects",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "1c44b4e7-5628-4d33-8138-d5cbcc411c6c", "exit_code": 0}
                ],
                "microservice": "Create SIP from Transfer",
                "uuid": "9c6f3a9a-c79d-4e88-8b7e-ade5a42be228",
                "link_uuid": "032cdc54-0b9b-4caf-86e8-10d63efbaec0",
                "name": "Check transfer directory for objects",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "06882a02-eec7-4de6-a6e8-4b7470917a12", "exit_code": 0},
                    {"uuid": "28b9c6f7-8853-495b-8d2a-3dfa6757d081", "exit_code": 0},
                    {"uuid": "345cd41b-3fee-4d6d-b9cc-a8b66ef2a7ba", "exit_code": 0},
                    {"uuid": "3b66c687-2e7d-4dda-9cd1-c69802add373", "exit_code": 0},
                    {"uuid": "5761aef4-8321-48e6-81de-9fe66eb470d1", "exit_code": 0},
                    {"uuid": "7f93065c-a9d0-4fda-be5e-f79bc5c9c34c", "exit_code": 0},
                    {"uuid": "b71c42e1-ed04-453a-bcca-45fa2995e9f0", "exit_code": 0},
                    {"uuid": "c1cecd7e-0ed7-46fe-8dd9-86c49bfde99a", "exit_code": 0},
                    {"uuid": "c49476cc-e677-4e6b-b73c-52721ab8123a", "exit_code": 0},
                    {"uuid": "e29078dd-b375-44b9-af2b-3454d2428ec9", "exit_code": 0},
                ],
                "microservice": "Assign file UUIDs and checksums",
                "uuid": "9fe8bcf7-583b-41ce-8c17-90fd3900fc43",
                "link_uuid": "52269473-5325-4a11-b38a-c4aafcbd8f54",
                "name": "Assign file UUIDs to objects",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "19b82242-9d12-470f-93ed-a5e3e16bd3ae", "exit_code": 0},
                    {"uuid": "48feda81-27c6-4c70-854b-6199b7ef16d5", "exit_code": 0},
                    {"uuid": "79b1ae79-4606-4c71-8c99-9ca1f2cc96ba", "exit_code": 0},
                    {"uuid": "8d32dd96-b8ae-45b6-ac96-caaa709d2c42", "exit_code": 0},
                    {"uuid": "8fc383a6-75b6-4066-ba28-86437994d600", "exit_code": 0},
                    {"uuid": "a8c74805-8fd5-4e81-a0f9-f843389ff315", "exit_code": 0},
                    {"uuid": "b01521e9-8f91-490e-bd2c-2f9be5a4a699", "exit_code": 0},
                    {"uuid": "b9d93893-9c43-4c2c-856d-4c9d8a75f993", "exit_code": 0},
                    {"uuid": "e7dffb14-5bb1-474f-b35b-1a57619c7a9d", "exit_code": 0},
                    {"uuid": "f48fa269-04fd-44bb-bc08-d8164225c1fb", "exit_code": 0},
                ],
                "microservice": "Characterize and extract metadata",
                "uuid": "a1914a8c-ecd0-4324-9323-69a8e3e1d069",
                "link_uuid": "303a65f6-a16f-4a06-807b-cb3425a30201",
                "name": "Characterize and extract metadata",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "3cfa73eb-3894-4749-8143-c3f4b18b250f", "exit_code": 0}
                ],
                "microservice": "Generate transfer structure report",
                "uuid": "b56158d2-2667-4853-8c7b-ab8480d656c8",
                "link_uuid": "6eca2676-b4ed-48d9-adb0-374e1d5c6e71",
                "name": "Move to processing directory",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "5d55e1bb-b9eb-46fd-b253-7c30779427e6", "exit_code": 0}
                ],
                "microservice": "Characterize and extract metadata",
                "uuid": "b5851196-17b5-4ffa-8693-2c6f9d3c3a01",
                "link_uuid": "1a136608-ae7b-42b4-bf2f-de0e514cfd47",
                "name": "Load rights",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "0bbf7baf-1641-434d-a636-5cfd19162377", "exit_code": 0}
                ],
                "microservice": "Create SIP from Transfer",
                "uuid": "b917087f-0004-4ae6-bf76-a12b7b5d4117",
                "link_uuid": "f378ec85-adcc-4ee6-ada2-bc90cfe20efb",
                "name": "Serialize Dublin Core metadata to disk",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "6927ea48-bbbe-4aa7-b2d3-f353fbfcf112", "exit_code": 0}
                ],
                "microservice": "Examine contents",
                "uuid": "b918e51a-c253-4048-9c0b-aa62de3f17b0",
                "link_uuid": "dae3c416-a8c2-4515-9081-6dbd7b265388",
                "name": "Move to examine contents",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "0b3f7be3-ca2d-429f-b643-a2896d70bab1", "exit_code": 0}
                ],
                "microservice": "Verify transfer compliance",
                "uuid": "b9de007f-77cd-414d-a0f9-3bb93eb074fe",
                "link_uuid": "45063ad6-f374-4215-a2c4-ac47be4ce2cd",
                "name": "Verify transfer compliance",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Identify DSpace files",
                "uuid": "bb579f26-3189-461c-b7b8-c9bfabf42aba",
                "link_uuid": "8ec0b0c1-79ad-4d22-abcd-8e95fcceabbc",
                "name": "Identify DSpace mets files",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Create SIP from Transfer",
                "uuid": "c6f06144-ba65-4c6d-9b77-63373e196fa6",
                "link_uuid": "bb194013-597c-4e4a-8493-b36d190f8717",
                "name": "Create SIP(s)",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "04bf53a1-9423-4ac3-92c5-10872abd2b79", "exit_code": 0},
                    {"uuid": "0796bc00-285a-4793-a2e3-ffd7e467c37c", "exit_code": 0},
                    {"uuid": "25978bd0-3890-4d32-8a8d-f4c79b95b457", "exit_code": 0},
                    {"uuid": "465b617f-37b4-486c-b3e3-1c9fc5660feb", "exit_code": 0},
                    {"uuid": "4bf6c81c-cbc9-4041-8816-64eb293aef7c", "exit_code": 0},
                    {"uuid": "4ef325dc-0bfa-4807-858c-7e3991f8a0d2", "exit_code": 0},
                    {"uuid": "60d2fc46-5ebc-4c03-800b-abc76891cae3", "exit_code": 0},
                    {"uuid": "77a0fd0d-61cb-4f2b-a6b6-824c24bdd50f", "exit_code": 0},
                    {"uuid": "7afc2346-7ed3-466c-bd49-86d70a4740ed", "exit_code": 0},
                    {"uuid": "8ad19529-b01b-42cf-a28f-e1c17a25cec3", "exit_code": 0},
                ],
                "microservice": "Assign file UUIDs and checksums",
                "uuid": "cc8ab98a-3420-441e-b623-af84f0d69b3a",
                "link_uuid": "28a9f8a8-0006-4828-96d5-892e6e279f72",
                "name": "Assign checksums and file sizes to objects",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "a6dfa4c2-c8b0-4281-a7d9-540c31b3e36c", "exit_code": 0}
                ],
                "microservice": "Clean up names",
                "uuid": "d4e51c50-bf55-406d-aab7-b9e1aada961d",
                "link_uuid": "a329d39b-4711-4231-b54e-b5958934dccb",
                "name": "Sanitize Transfer name",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "05c171c7-6b43-4cbd-8242-ee62879a7fc0", "exit_code": 0},
                    {"uuid": "4a355674-c86e-4bb2-88e4-9d918c0a0aea", "exit_code": 0},
                    {"uuid": "51b437ad-80c2-48d9-a6f3-813822bfda9d", "exit_code": 0},
                    {"uuid": "57747f94-e35f-4578-a78c-057a7dae3360", "exit_code": 0},
                    {"uuid": "6eb67a5a-7c3c-4b3b-8c41-c27c9817adea", "exit_code": 0},
                    {"uuid": "98f69e82-7bbd-463e-87e0-171f23332fd0", "exit_code": 0},
                    {"uuid": "9e40016a-4f63-48c9-96fe-2adacdd5665a", "exit_code": 0},
                    {"uuid": "ba422384-096f-41a5-990e-1d614a37c609", "exit_code": 0},
                    {"uuid": "d016bbe2-9d8a-4841-9311-8801186cd8a4", "exit_code": 0},
                    {"uuid": "d5a2883b-7b56-4ba2-98ee-9978f9e2587d", "exit_code": 0},
                ],
                "microservice": "Identify file format",
                "uuid": "dbf1ffb3-2f9e-4764-9646-0147d8ba5ed4",
                "link_uuid": "2522d680-c7d9-4d06-8b11-a28d8bd8a71f",
                "name": "Identify file format",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Identify file format",
                "uuid": "de4aaa9f-0ab1-44fc-be83-9d7fa4bf4b5d",
                "link_uuid": "f09847c2-ee51-429a-9478-a860477f6b8d",
                "name": "Do you want to perform file format identification?",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "13000fc4-d421-4d63-ba2b-0fb7c217d166", "exit_code": 0}
                ],
                "microservice": "Create SIP from Transfer",
                "uuid": "e2fec1aa-bd72-4577-96f4-64bff7a698b3",
                "link_uuid": "3e75f0fa-2a2b-4813-ba1a-b16b4be4cac5",
                "name": "Move to SIP creation directory for completed transfers",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "7501302f-19d3-4142-9dc6-cee3e1fb76c5", "exit_code": 0}
                ],
                "microservice": "Scan for viruses",
                "uuid": "eb58e65e-47bb-4e00-831d-0707d5566969",
                "link_uuid": "d7e6404a-a186-4806-a130-7e6d27179a15",
                "name": "Move to processing directory",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "36f3376c-07a8-4349-bbb5-e3e2f09ad1cf", "exit_code": 0}
                ],
                "microservice": "Create SIP from Transfer",
                "uuid": "eeebe9bf-6954-4d23-99e5-41e774b6fe1e",
                "link_uuid": "39a128e3-c35d-40b7-9363-87f75091e1ff",
                "name": "Create SIP from transfer objects",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Identify DSpace files",
                "uuid": "f4b95ada-5551-4566-8d4a-5e513ef30b68",
                "link_uuid": "2fd123ea-196f-4c9c-95c0-117aa65ed9c6",
                "name": "Verify checksums in fileSec of DSpace METS files",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Create SIP from Transfer",
                "uuid": "f58bb262-ad28-4155-a1c1-edb9de5083bd",
                "link_uuid": "b04e9232-2aea-49fc-9560-27349c8eba4e",
                "name": "Load options to create SIPs",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Parse external files",
                "uuid": "fb7d3456-8abb-431d-b0ff-2858f307e8a0",
                "link_uuid": "ec3c965c-c056-47e3-a551-ad1966e00824",
                "name": "Determine if Dataverse METS XML needs to be parsed",
            },
            {
                "status": "COMPLETE",
                "tasks": [],
                "microservice": "Verify transfer compliance",
                "uuid": "ff04a265-e40f-469c-89af-d125727e24c8",
                "link_uuid": "f2a019ea-0601-419c-a475-1b96a927a2fb",
                "name": "Set specialized processing link",
            },
        ],
        [
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "81d80780-d4bf-4f70-94c4-3de13c9d7d3e", "exit_code": 0}
                ],
                "microservice": "Clean up names",
                "uuid": "5d582d29-9741-47d7-ad76-2aec612c410f",
                "link_uuid": "2584b25c-8d98-44b7-beca-2b3ea2ea2505",
                "name": "Sanitize object's file and directory names",
            },
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "a6dfa4c2-c8b0-4281-a7d9-540c31b3e36c", "exit_code": 0}
                ],
                "microservice": "Clean up names",
                "uuid": "d4e51c50-bf55-406d-aab7-b9e1aada961d",
                "link_uuid": "a329d39b-4711-4231-b54e-b5958934dccb",
                "name": "Sanitize Transfer name",
            },
        ],
        [
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "3e722b0c-455a-41f4-8aca-de2e21894531", "exit_code": 0}
                ],
                "microservice": "Verify transfer compliance",
                "uuid": "162484b8-65cc-4e0b-9b2d-e02e7a52e2c4",
                "link_uuid": "87e7659c-d5de-4541-a09c-6deec966a0c0",
                "name": "Verify mets_structmap.xml compliance",
            }
        ],
        [
            {
                "status": "COMPLETE",
                "tasks": [
                    {"uuid": "9260102c-bf06-4577-b3f0-d656f2ae649e", "exit_code": 0}
                ],
                "microservice": "Verify transfer checksum",
                "uuid": "45227afe-9ad5-4d70-ab4e-fc24fbbdb3f2",
                "link_uuid": "5e4bd4e8-d158-4c2a-be89-51e3e9bd4a06",
                "name": "Verify metadata directory checksums",
            }
        ],
    ],
)
def test_get_jobs(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={"microservice": "Clean up names"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={"link_uuid": "87e7659c-d5de-4541-a09c-6deec966a0c0"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={"name": "Verify metadata directory checksums"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
    ]


@mock.patch("requests.request")
def test_get_status(mock_request: mock.Mock):
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
    with pytest.raises(requests.exceptions.Timeout):
        client.get_unit_status(transfer_uuid)
    mock_request.reset_mock()


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "default": False,
            "description": "AM Client unit test description",
            "enabled": True,
            "path": "/this/is/a/path",
            "pipeline": [
                "/api/v2/pipeline/26bda073-753b-42bd-b312-f39b7db4921d/",
                "/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/",
            ],
            "purpose": "TS",
            "quota": None,
            "relative_path": "this/is/a/path",
            "resource_uri": "/api/v2/location/e36a7649-74d7-4320-ba29-424ee3d6b837/",
            "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
            "used": "0",
            "uuid": "e36a7649-74d7-4320-ba29-424ee3d6b837",
        },
        {
            "default": True,
            "description": "AM Client unit test description",
            "enabled": True,
            "path": "/this/is/another/path",
            "pipeline": ["/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/"],
            "purpose": "AS",
            "quota": None,
            "relative_path": "this/is/another/path",
            "resource_uri": "/api/v2/location/e7648d04-2ff9-41bc-baab-060c6b7ec02c/",
            "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
            "used": "0",
            "uuid": "e7648d04-2ff9-41bc-baab-060c6b7ec02c",
        },
        {
            "default": False,
            "description": "",
            "enabled": True,
            "path": "/this/is/a/path",
            "pipeline": ["/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/"],
            "purpose": "DS",
            "quota": None,
            "relative_path": "this/is/a/path",
            "resource_uri": "/api/v2/location/7ba89b2f-9135-47dc-ba32-2799ee80cd9b/",
            "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
            "used": "0",
            "uuid": "7ba89b2f-9135-47dc-ba32-2799ee80cd9b",
        },
    ],
)
def test_create_location(call_url: mock.Mock):
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

    assert response.get("description") == test_desc, "Description returned is incorrect"
    assert response.get("relative_path") == test_path_1, "Path returned is incorrect"
    assert uri_pipeline_1 and uri_pipeline_2 in response.get(
        "pipeline"
    ), "The specified pipelines are not in the API response"
    assert response.get("resource_uri"), "Resource URI is not in response as expected"
    assert response.get("uuid"), "UUID for the new location not returned"
    assert response.get("default") is False, "Space default has returned incorrectly"
    assert (
        response.get("purpose") == purpose_transfer
    ), "Incorrect purpose assigned to newly created location"
    assert response.get("space") == uri_space, "Incorrect URI for our space returned"

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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/",
            method="POST",
            data=json.dumps(
                {
                    "description": "AM Client unit test description",
                    "pipeline": [
                        "/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/",
                        "/api/v2/pipeline/26bda073-753b-42bd-b312-f39b7db4921d/",
                    ],
                    "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
                    "default": False,
                    "purpose": "TS",
                    "relative_path": "this/is/a/path",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/",
            method="POST",
            data=json.dumps(
                {
                    "description": "AM Client unit test description",
                    "pipeline": [
                        "/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/"
                    ],
                    "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
                    "default": True,
                    "purpose": "AS",
                    "relative_path": "this/is/another/path",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/",
            method="POST",
            data=json.dumps(
                {
                    "description": "",
                    "pipeline": [
                        "/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/"
                    ],
                    "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
                    "default": False,
                    "purpose": "DS",
                    "relative_path": "this/is/a/path",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        ),
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 400,
                }
            )
        ),
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 400,
                }
            )
        ),
    ],
)
def test_create_location_failure_responses(call_url: mock.Mock):
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
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
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
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
        response.get("valid_purposes") == amclient.AMClient().list_location_purposes()
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/",
            method="POST",
            data=json.dumps(
                {
                    "description": "AM Client unit test description",
                    "pipeline": [
                        "/api/v2/pipeline/d6aeb4e0-e836-4768-8225-26e5720950d3/"
                    ],
                    "space": "/api/v2/space/badf00d3-c759-443f-95c9-0fa813034731/",
                    "default": False,
                    "purpose": "AS",
                    "relative_path": "this/is/a/path",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            "http://192.168.168.192:8000/api/v2/location/",
            method="POST",
            data=json.dumps(
                {
                    "description": "AM Client unit test description",
                    "pipeline": [
                        "/api/v2/pipeline/badf00d3-753b-42bd-b312-f39b7db4921d/"
                    ],
                    "space": "/api/v2/space/30226523-c759-443f-95c9-0fa813034731/",
                    "default": False,
                    "purpose": "DS",
                    "relative_path": "this/is/a/path",
                }
            ),
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        ),
    ]


@mock.patch("requests.request")
def test_validate_csv(mock_request: mock.Mock, tmp_path):
    tmp_csv = tmp_path / "validate_me.csv"
    tmp_csv.write_text(
        "file,basis,status,determination_date,jurisdiction,start_date,end_date,terms,citation,note,grant_act,grant_restriction,grant_start_date,grant_end_date,grant_note,doc_id_type,doc_id_value,doc_id_role\n"
        "objects/image1.tif,copyright,copyrighted,2011-01-01,ca,2011-01-01,2013-12-31,,ha,Note about copyright.,disseminate,disallow,2011-01-01,2013-12-31,Grant note,Copyright documentation identifier type.,Copyright documentation identifier value.,Copyright documentation identifier role."
    )
    client = amclient.AMClient(
        am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
    )
    filepath = tmp_csv.as_posix()
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


@mock.patch(
    "amclient.utils._call_url", side_effect=[{"message": "Approval successful."}]
)
def test_approve_partial_reingest(call_url: mock.Mock):
    response = amclient.AMClient(
        am_api_key=AM_API_KEY,
        am_user_name=AM_USER_NAME,
        am_url=AM_URL,
        sip_uuid="7d41223f-76af-4732-96a9-fb06aa5feaed",
    ).approve_partial_reingest()
    assert response["message"] == "Approval successful."

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/reingest/approve/",
            method="POST",
            data={"uuid": "7d41223f-76af-4732-96a9-fb06aa5feaed"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 400,
                }
            )
        ),
    ],
)
def test_approve_non_existing_partial_reingest(call_url: mock.Mock):
    response = amclient.AMClient(
        am_api_key=AM_API_KEY,
        am_user_name=AM_USER_NAME,
        am_url=AM_URL,
        sip_uuid="4ceaf490-cf9b-425a-adb7-8358a7a68fa9",
    ).approve_partial_reingest()
    assert (
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/reingest/approve/",
            method="POST",
            data={"uuid": "4ceaf490-cf9b-425a-adb7-8358a7a68fa9"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[{"error": False, "message": "Metadata files added successfully."}],
)
def test_copy_metadata_files(call_url: mock.Mock):
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

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/copy_metadata_files/",
            method="POST",
            data={
                "sip_uuid": "f8beb140-3149-471c-861a-249e1d851c92",
                "source_paths[]": [
                    b"NGQwZGUwYWEtMjY1OC00ZjIxLWJiMDktZDczMGI4NGIyYjAxOi9ob21lL2FyY2hpdmVtYXRpY2EvYXJjaGl2ZW1hdGljYS1zYW1wbGVkYXRhL21ldGFkYXRhLmNzdg==",
                    b"NGQwZGUwYWEtMjY1OC00ZjIxLWJiMDktZDczMGI4NGIyYjAxOi9ob21lL2FyY2hpdmVtYXRpY2EvYXJjaGl2ZW1hdGljYS1zYW1wbGVkYXRhL21kdXBkYXRlLnppcA==",
                ],
            },
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


def _test_copy_metadata_files_with_empty_parameter(*params):
    response = amclient.AMClient(
        am_api_key=AM_API_KEY,
        am_user_name=AM_USER_NAME,
        am_url=AM_URL,
        enhanced_errors=True,
    ).copy_metadata_files(*params)
    assert (
        errors.error_lookup(response) == errors.error_codes[errors.ERR_INVALID_RESPONSE]
    )
    assert response.message == {
        "error": True,
        "message": "sip_uuid and source_paths[] both required.",
    }


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 400,
                    "json.return_value": {
                        "error": True,
                        "message": "sip_uuid and source_paths[] both required.",
                    },
                }
            )
        ),
    ],
)
def test_copy_metadata_files_with_empty_sip_uuid(call_url: mock.Mock):
    _test_copy_metadata_files_with_empty_parameter(
        "",
        [
            (
                "4d0de0aa-2658-4f21-bb09-d730b84b2b01",
                "/home/archivematica/archivematica-sampledata/metadata.csv",
            ),
        ],
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/copy_metadata_files/",
            method="POST",
            data={
                "sip_uuid": "",
                "source_paths[]": [
                    b"NGQwZGUwYWEtMjY1OC00ZjIxLWJiMDktZDczMGI4NGIyYjAxOi9ob21lL2FyY2hpdmVtYXRpY2EvYXJjaGl2ZW1hdGljYS1zYW1wbGVkYXRhL21ldGFkYXRhLmNzdg=="
                ],
            },
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(
            response=mock.Mock(
                **{
                    "status_code": 400,
                    "json.return_value": {
                        "error": True,
                        "message": "sip_uuid and source_paths[] both required.",
                    },
                }
            )
        ),
    ],
)
def test_copy_metadata_files_with_empty_source_paths(call_url: mock.Mock):
    _test_copy_metadata_files_with_empty_parameter(
        "f8beb140-3149-471c-861a-249e1d851c92", []
    )

    assert call_url.mock_calls == [
        mock.call(
            "http://192.168.168.192/api/ingest/copy_metadata_files/",
            method="POST",
            data={
                "sip_uuid": "f8beb140-3149-471c-861a-249e1d851c92",
                "source_paths[]": [],
            },
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


if __name__ == "__main__":
    unittest.main()
