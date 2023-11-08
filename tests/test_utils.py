import pytest

from amclient import utils


@pytest.mark.parametrize(
    "test_package",
    [
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
    ],
)
def test_package_name_from_path(test_package):
    """Test that package_name_from_path returns expected results."""
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
    assert package_name_without_uuid == test_package["package_name_without_uuid"]
