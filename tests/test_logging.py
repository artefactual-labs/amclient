import os
import subprocess
import sys
from unittest import mock

import pytest

from amclient import loggingconfig


def test_import_does_not_create_a_temporary_directory(tmp_path):
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(tmp_path),
    }

    subprocess.run(
        [sys.executable, "-c", "import amclient"],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )

    assert list(tmp_path.iterdir()) == []


@mock.patch("amclient.loggingconfig.mkdtemp")
def test_get_log_file_name_creates_the_default_directory_when_needed(
    mkdtemp: mock.Mock, tmp_path
):
    mkdtemp.return_value = str(tmp_path)

    log_file_name = loggingconfig.get_log_file_name(None)

    assert log_file_name == str(tmp_path / "amclient.log")


@mock.patch("amclient.loggingconfig.mkdtemp")
def test_get_log_file_name_preserves_an_explicit_path(mkdtemp: mock.Mock, tmp_path):
    expected = str(tmp_path / "custom.log")

    log_file_name = loggingconfig.get_log_file_name(expected)

    assert log_file_name == expected
    mkdtemp.assert_not_called()


@mock.patch("amclient.loggingconfig.logging.config.dictConfig")
def test_setup_configures_console_and_file_logging(dict_config: mock.Mock, tmp_path):
    log_file_name = str(tmp_path / "amclient.log")

    loggingconfig.setup("DEBUG", log_file_name)

    config = dict_config.call_args.args[0]
    assert config["disable_existing_loggers"] is False
    assert config["handlers"]["console"] == {
        "class": "logging.StreamHandler",
        "formatter": "default",
    }
    assert config["handlers"]["file"] == {
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "default",
        "filename": log_file_name,
        "backupCount": 2,
        "maxBytes": 10 * 1024,
        "delay": True,
    }
    assert config["loggers"] == {
        "amclient": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
        },
        "requests.packages.urllib3": {
            "level": "DEBUG",
            "handlers": ["file"],
        },
    }


@pytest.mark.parametrize(
    ("quiet", "verbose", "expected"),
    [
        (0, 0, "INFO"),
        (1, 0, "WARNING"),
        (2, 0, "ERROR"),
        (3, 0, "ERROR"),
        (0, 1, "DEBUG"),
        (0, 2, "DEBUG"),
        (1, 1, "INFO"),
    ],
)
def test_set_log_level_from_quiet_and_verbose(quiet, verbose, expected):
    assert loggingconfig.set_log_level(None, quiet, verbose) == expected


@pytest.mark.parametrize("log_level", ["ERROR", "WARNING", "INFO", "DEBUG"])
def test_set_log_level_preserves_an_explicit_level(log_level):
    assert loggingconfig.set_log_level(log_level, quiet=2, verbose=2) == log_level
