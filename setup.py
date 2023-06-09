"""A setuptools based setup module.
See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""
import codecs
import re
from os import path

from setuptools import find_packages
from setuptools import setup

here = path.abspath(path.dirname(__file__))


def read(*parts):
    with codecs.open(path.join(here, *parts), "r") as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


# Get the long description from the relevant file
with codecs.open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()


setup(
    name="amclient",
    version=find_version("amclient/version.py"),
    description="Archivematica API client library.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/artefactual-labs/amclient/",
    author="Artefactual",
    author_email="info@artefactual.com",
    license="AGPL",
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="Archivematica API Archivematica-Storage-Service SDK",
    packages=find_packages(exclude=["fixtures", "requirements", "tests*"]),
    install_requires=["requests<3", "urllib3<2"],
    include_package_data=True,
    python_requires=">=3.6",
    # Entry point for the amclient binary
    entry_points={"console_scripts": ["amclient=amclient.amclient:main"]},
)
