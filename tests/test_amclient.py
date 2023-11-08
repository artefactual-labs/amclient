import hashlib
import json
import os
import unittest
import uuid
from binascii import hexlify
from typing import Dict
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
            f"{AM_URL}/api/transfer/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/transfer/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/transfer/9bc0b1c7-658f-46d4-9a6f-4a282e8a8ee5/delete/",
            method="DELETE",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/transfer/d7bd50b5-6473-4e9f-8555-8515e55d0a16/delete/",
            method="DELETE",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/transfer/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/transfer/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/transfer/completed",
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
            f"{AM_URL}/api/transfer/unapproved",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/transfer/unapproved",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{SS_URL}/api/v2/location/{TRANSFER_SOURCE_UUID}/browse/",
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
            f"{SS_URL}/api/v2/location/{TRANSFER_SOURCE_UUID}/browse/",
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
            f"{SS_URL}/api/v2/location/{TRANSFER_SOURCE_UUID}/browse/",
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
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=AIP",
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
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
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
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=AIP",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&package_type=AIP&limit=1&offset=2",
            method="GET",
            params={},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&package_type=AIP&api_key={SS_API_KEY}&limit=1&offset=3",
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
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
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
            f"{SS_URL}/api/v2/file/",
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
            f"{SS_URL}/api/v2/file/?username={SS_USER_NAME}&api_key={SS_API_KEY}&limit=1&offset=1&package_type=DIP",
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
            f"{SS_URL}/api/v2/file/c0e37bab-e51e-482d-a066-a277330de9a7/download/",
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
        mock.Mock(**{"status_code": 404}),
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
            f"{SS_URL}/api/v2/file/bad dip uuid/download/",
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
            f"{SS_URL}/api/v2/file/216dd8a6-c366-41f8-b11e-0c70814b3992/download/",
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
        mock.Mock(**{"status_code": 404}),
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
            f"{SS_URL}/api/v2/file/bad-aip-uuid/download/",
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
            f"{SS_URL}/api/v2/file/fccc77cf-2045-44ed-9ddc-b335c63d5f9a/delete_aip/",
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
            f"{SS_URL}/api/v2/file/bad-aip-uuid/delete_aip/",
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
            f"{AM_URL}/api/ingest/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/ingest/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/ingest/2d75323c-70a0-4d5f-a8d0-762e729fc2b9/delete/",
            method="DELETE",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
            headers=None,
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/ingest/57d7faff-c397-4485-9035-6eaeb5c35636/delete/",
            method="DELETE",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
            headers=None,
            assume_json=True,
        ),
    ]


@mock.patch("amclient.utils._call_url")
@pytest.mark.parametrize(
    "fixture",
    [
        {
            "uuid": "fdf1f7d4-7b0e-46d7-a1cc-e1851f8b92ed",
            "unit_type": "transfer",
            "expected": {"removed": True},
            "data_type": dict,
            "call_url_side_effect": {"removed": True},
        },
        {
            "uuid": "777a9d9e-baad-f00d-8c7e-00b75773672d",
            "unit_type": "transfer",
            "expected": errors.ERR_INVALID_RESPONSE,
            "data_type": int,
            "call_url_side_effect": requests.exceptions.HTTPError(
                response=mock.Mock(**{"status_code": 404})
            ),
        },
        {
            "uuid": "b72afa68-9e82-410d-9235-02fa10512e14",
            "unit_type": "ingest",
            "expected": {"removed": True},
            "data_type": dict,
            "call_url_side_effect": {"removed": True},
        },
        {
            "uuid": "777a9d9e-baad-f00d-8c7e-00b75773672d",
            "unit_type": "ingest",
            "expected": errors.ERR_INVALID_RESPONSE,
            "data_type": int,
            "call_url_side_effect": requests.exceptions.HTTPError(
                response=mock.Mock(**{"status_code": 404})
            ),
        },
    ],
)
def test_hide_units(call_url: mock.Mock, fixture: Dict):
    """Test the hiding of a unit type (transfer or ingest) via the
    Archivematica API.
    """
    call_url.side_effect = [fixture["call_url_side_effect"]]
    response = amclient.AMClient(
        am_api_key=AM_API_KEY, am_user_name=AM_USER_NAME, am_url=AM_URL
    ).hide_unit(fixture["uuid"], fixture["unit_type"])
    assert isinstance(response, fixture["data_type"])
    assert response == fixture["expected"]

    assert call_url.mock_calls == [
        mock.call(
            f"{AM_URL}/api/{fixture['unit_type']}/{fixture['uuid']}/delete/",
            method="DELETE",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/ingest/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
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
            f"{AM_URL}/api/ingest/completed",
            method="GET",
            params={"username": AM_USER_NAME, "api_key": AM_API_KEY},
            headers=None,
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        {
            "objects": [
                {
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
            f"{SS_URL}/api/v2/pipeline/",
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
            f"{SS_URL}/api/v2/pipeline/",
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
            "message": "Fetched status for 63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9 successfully.",
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
            f"{AM_URL}/api/transfer/status/63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9/",
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
            f"{AM_URL}/api/transfer/status/7bffc8f7-baad-f00d-8120-b1c51c2ab5db/",
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
            "message": "Fetched status for 23129471-09e3-467e-88b6-eb4714afb5ac successfully.",
            "type": "SIP",
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
            f"{AM_URL}/api/ingest/status/23129471-09e3-467e-88b6-eb4714afb5ac/",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 400})),
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
            f"{AM_URL}/api/ingest/status/63fcc1b0-f83d-47e6-ac9d-a8f8d1fc2ab9/",
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
            f"{AM_URL}/api/processing-configuration/default",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=False,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 404})),
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
            f"{AM_URL}/api/processing-configuration/badf00d",
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
            f"{AM_URL}/api/transfer/approve/",
            method="POST",
            data={"type": "standard", "directory": b"approve_1"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 500})),
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
            f"{AM_URL}/api/transfer/approve/",
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
            f"{SS_URL}/api/v2/file/df8e0c68-3bda-4d1d-8493-789f7dec47f5/reingest/",
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
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 404})),
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
            f"{SS_URL}/api/v2/file/bb033eff-131e-48d5-980f-c4edab0cb038/reingest/",
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
            "package_type": "AIP",
            "status": "UPLOADED",
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
            f"{SS_URL}/api/v2/file/23129471-09e3-467e-88b6-eb4714afb5ac",
            method="GET",
            params=None,
            headers={"Authorization": f"ApiKey {SS_USER_NAME}:{SS_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 404})),
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
            f"{SS_URL}/api/v2/file/23129471-baad-f00d-88b6-eb4714afb5ac",
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
            "meta": {"next": None},
            "objects": [
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/5843/53f3/c402/4ff5/a00c/59d0/e133/4683/deleted_1-584353f3-c402-4ff5-a00c-59d0e1334683.7z",
                    "package_type": "AIP",
                    "status": "DELETED",
                    "uuid": "584353f3-c402-4ff5-a00c-59d0e1334683",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/6f54/7b25/aea0/4161/9f68/316f/c246/5fd9/deleted_2-6f547b25-aea0-4161-9f68-316fc2465fd9.7z",
                    "package_type": "AIP",
                    "status": "DELETED",
                    "uuid": "6f547b25-aea0-4161-9f68-316fc2465fd9",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/6d32/a85f/6715/43af/947c/83c9/d7f0/deac/transfer_1-6d32a85f-6715-43af-947c-83c9d7f0deac.7z",
                    "package_type": "AIP",
                    "status": "UPLOADED",
                    "uuid": "6d32a85f-6715-43af-947c-83c9d7f0deac",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/6f19/8696/e3b6/4f45/8ab3/b4cd/4afd/921a/transfer_2-6f198696-e3b6-4f45-8ab3-b4cd4afd921a.7z",
                    "package_type": "AIP",
                    "status": "UPLOADED",
                    "uuid": "6f198696-e3b6-4f45-8ab3-b4cd4afd921a",
                },
                {
                    "current_full_path": "/var/archivematica/sharedDirectory/watchedDirectories/storeAIP/9c5e/dcdc/3e3f/499d/a016/a43b/9db8/75b1/transfer_3-9c5edcdc-3e3f-499d-a016-a43b9db875b1.7z",
                    "package_type": "AIP",
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
            f"{SS_URL}/api/v2/file/",
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
            "meta": {"next": None, "total_count": 7},
            "objects": [
                {
                    "purpose": "TS",
                    "uuid": "d1184f7f-d755-4c8d-831a-a3793b88f760",
                },
                {
                    "purpose": "AS",
                    "uuid": "471ff191-2c03-441d-b1d6-0c39d27a6b66",
                },
                {
                    "purpose": "DS",
                    "uuid": "b7783482-a2ca-4dc8-9f3e-6305c7569268",
                },
                {
                    "purpose": "BL",
                    "uuid": "77dd226a-39b2-4217-b2a4-e17dad1beaae",
                },
                {
                    "purpose": "SS",
                    "uuid": "e8f346b7-0090-44b5-8b31-bff7f9d74e98",
                },
                {
                    "purpose": "AR",
                    "uuid": "52bea1a4-0853-4082-8a63-3540b79d1772",
                },
                {
                    "purpose": "CP",
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
            f"{SS_URL}/api/v2/location/",
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
            f"{AM_URL}/api/v2beta/package/",
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
            f"{AM_URL}/api/v2beta/package/",
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
            f"{AM_URL}/api/v2beta/package/",
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
            f"{SS_URL}/api/v2/file/2ad1bf0d-23fa-44e0-a128-9feadfe22c42/extract_file/?relative_path_to_file=amclient-transfer_1-2ad1bf0d-23fa-44e0-a128-9feadfe22c42/data/objects/bird.mp3",
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
            f"{SS_URL}/api/v2/file/2ad1bf0d-23fa-44e0-a128-9feadfe22c42/extract_file/?relative_path_to_file=amclient-transfer_1-2ad1bf0d-23fa-44e0-a128-9feadfe22c42/data/objects/bird.mp3",
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
            f"{SS_URL}/api/v2/file/2ad1bf0d-23fa-44e0-a128-9feadfe22c42/extract_file/?relative_path_to_file=amclient-transfer_1-2ad1bf0d-23fa-44e0-a128-9feadfe22c42/data/objects/bird.mp3",
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
            "meta": {},
            "objects": [
                {
                    "current_path": "64f4/cb73/60bc/49f2/ab75/d83c/9365/b7d3/mkv-characterization-64f4cb73-60bc-49f2-ab75-d83c9365b7d3.7z",
                    "package_type": "AIP",
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
            f"{SS_URL}/api/v2/file/64f4cb73-60bc-49f2-ab75-d83c9365b7d3/extract_file/?relative_path_to_file=mkv-characterization-64f4cb73-60bc-49f2-ab75-d83c9365b7d3/data/METS.64f4cb73-60bc-49f2-ab75-d83c9365b7d3.xml",
            params={
                "username": SS_USER_NAME,
                "api_key": SS_API_KEY,
            },
            stream=True,
        )
    ]

    assert call_url.mock_calls == [
        mock.call(
            f"{SS_URL}/api/v2/file/",
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
                ],
                "microservice": "Scan for viruses",
                "uuid": "01233bfd-5405-4232-a098-9e1234dd7702",
                "link_uuid": "1c2550f1-3fc0-45d8-8bc4-4c06d720283b",
                "name": "Scan for viruses",
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
            f"{AM_URL}/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={"microservice": "Clean up names"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
            method="GET",
            params={"link_uuid": "87e7659c-d5de-4541-a09c-6deec966a0c0"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        ),
        mock.call(
            f"{AM_URL}/api/v2beta/jobs/ca480d94-892c-4d99-bbb1-290698406571",
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
            f"{SS_URL}/api/v2/location/",
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
            f"{SS_URL}/api/v2/location/",
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
            f"{SS_URL}/api/v2/location/",
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
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 400})),
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 400})),
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
            f"{SS_URL}/api/v2/location/",
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
            f"{SS_URL}/api/v2/location/",
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
            f"{AM_URL}/api/ingest/reingest/approve/",
            method="POST",
            data={"uuid": "7d41223f-76af-4732-96a9-fb06aa5feaed"},
            headers={"Authorization": f"ApiKey {AM_USER_NAME}:{AM_API_KEY}"},
            assume_json=True,
        )
    ]


@mock.patch(
    "amclient.utils._call_url",
    side_effect=[
        requests.exceptions.HTTPError(response=mock.Mock(**{"status_code": 400})),
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
            f"{AM_URL}/api/ingest/reingest/approve/",
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
            f"{AM_URL}/api/ingest/copy_metadata_files/",
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
            f"{AM_URL}/api/ingest/copy_metadata_files/",
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
            f"{AM_URL}/api/ingest/copy_metadata_files/",
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
