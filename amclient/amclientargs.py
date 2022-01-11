#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Archivematica Client Argument Parser

import argparse
from collections import namedtuple

try:
    import defaults
    import version
except ImportError:
    from amclient import defaults, version

# Reusable argument constants (for CLI), E.g. arguments without reasonable defaults and are required to complete an API call.
Arg = namedtuple("Arg", ["name", "help", "type"])
AIP_UUID = Arg(name="aip_uuid", help="UUID of the target AIP", type=None)
DIP_UUID = Arg(name="dip_uuid", help="UUID of the target DIP", type=None)
SIP_UUID = Arg(name="sip_uuid", help="UUID of the target SIP", type=None)
TRANSFER_UUID = Arg(name="transfer_uuid", help="UUID of the target Transfer", type=None)
UNIT_UUID = Arg(name="unit_uuid", help="UUID of the target unit", type=None)
AM_API_KEY = Arg(name="am_api_key", help="Archivematica API key", type=None)
SS_API_KEY = Arg(name="ss_api_key", help="Storage Service API key", type=None)
TRANSFER_SOURCE = Arg(name="transfer_source", help="Transfer source UUID", type=None)
PACKAGE_UUID = Arg(
    name="package_uuid", help="UUID of the package in the storage service", type=None
)
PIPELINE_UUID = Arg(name="pipeline_uuid", help="UUID of the pipeline to use", type=None)
PIPELINE_UUIDS = Arg(
    name="pipeline_uuids",
    help="Single value or comma-separated list of pipelines to associate with a storage location",
    type=None,
)
TRANSFER_DIRECTORY = Arg(
    name="transfer_directory",
    help="Directory of a potential Archivematica transfer",
    type=None,
)
RELATIVE_PATH = Arg(
    name="relative_path",
    help="Relative path to a file in an Archivematica package",
    type=None,
)
SPACE_UUID = Arg(
    name="space_uuid", help="UUID of the space to add the location to", type=None
)
SPACE_RELATIVE_PATH = Arg(
    name="space_relative_path", help="Path relative to a storage space", type=None
)
LOCATION_PURPOSE = Arg(
    name="location_purpose",
    help='Purpose of storage space location valid choices: "AR", "AS", "CP", "DS", "SD", "SS", "BL", "TS", "RP"',
    type=None,
)
EVENT_REASON = Arg(
    name="event_reason", help="Event reason for package deletion request", type=None
)
SS_USER_ID = Arg(
    name="ss_user_id",
    help="ID of Storage Service user making package deletion request, e.g. 1",
    type=None,
)
SS_USER_EMAIL = Arg(
    name="ss_user_email",
    help="Email address of Storage Service user making package deletion request",
    type=None,
)
# Reusable option constants (for CLI), E.g. arguments with reasonable defaults or are not required to complete an API call.
Opt = namedtuple("Opt", ["name", "metavar", "help", "default", "type"])
AM_URL = Opt(
    name="am-url",
    metavar="URL",
    help="Archivematica URL. Default: {0}".format(defaults.DEF_AM_URL),
    default=defaults.DEF_AM_URL,
    type=None,
)
AM_USER_NAME = Opt(
    name="am-user-name",
    metavar="USERNAME",
    help="Archivematica username. Default: {0}".format(defaults.DEF_USER_NAME),
    default=defaults.DEF_USER_NAME,
    type=None,
)
DIRECTORY = Opt(
    name="directory",
    metavar="DIR",
    help="Directory path to save the package in",
    default=None,
    type=None,
)
OUTPUT_MODE = Opt(
    name="output-mode",
    metavar="MODE",
    help="How to print output, JSON (default) or Python",
    default="json",
    type=None,
)
SS_URL = Opt(
    name="ss-url",
    metavar="URL",
    help="Storage Service URL. Default: {0}".format(defaults.DEF_SS_URL),
    default=defaults.DEF_SS_URL,
    type=None,
)
SS_USER_NAME = Opt(
    name="ss-user-name",
    metavar="USERNAME",
    help="Storage Service username. Default: {0}".format(defaults.DEF_USER_NAME),
    default=defaults.DEF_USER_NAME,
    type=None,
)
TRANSFER_PATH = Opt(
    name="transfer-path",
    metavar="PATH",
    help='Relative path within the Transfer Source. Default: ""',
    default="",
    type=None,
)
PROCESSING_CONFIG = Opt(
    name="processing-config",
    metavar="PROCESSING",
    help="Processing configuration. Default: {0}".format(
        defaults.DEFAULT_PROCESSING_CONFIG
    ),
    default=defaults.DEFAULT_PROCESSING_CONFIG,
    type=None,
)
REINGEST_TYPE = Opt(
    name="reingest-type",
    metavar="REINGEST",
    help="Reingest type. Default: {0}".format(defaults.DEFAULT_REINGEST_TYPE),
    default=defaults.DEFAULT_REINGEST_TYPE,
    type=None,
)
TRANSFER_TYPE = Opt(
    name="transfer-type",
    metavar="TRANSFER",
    help="Reingest type. Default: {0}".format(defaults.DEFAULT_TRANSFER_TYPE),
    default=defaults.DEFAULT_TRANSFER_TYPE,
    type=None,
)
TRANSFER_SOURCE_OPT = Opt(
    name="transfer-source",
    metavar="TRANSFERSOURCE",
    help="Transfer source UUID",
    default=None,
    type=None,
)
SAVEAS_FILENAME = Opt(
    name="saveas-filename",
    metavar="SAVEASFILENAME",
    help="A filename to save an extracted file as",
    default=None,
    type=None,
)
TRANSFER_NAME = Opt(
    name="transfer-name",
    metavar="TRANSFERNAME",
    help="A name for the transfer",
    default="amclient-transfer",
    type=None,
)
JOB_MICROSERVICE = Opt(
    name="job-microservice",
    metavar="JOBMICROSERVICE",
    help="Filter by microservice",
    default=None,
    type=None,
)
JOB_LINK_UUID = Opt(
    name="job-link-uuid",
    metavar="JOBLINKUUID",
    help="Filter by job link UUID",
    default=None,
    type=None,
)
JOB_NAME = Opt(
    name="job-name", metavar="JOBNAME", help="Filter by name", default=None, type=None
)
LOCATION_DESCRIPTION = Opt(
    name="location-description",
    metavar="LOCATIONDESCRIPTION",
    help="Description for the storage location",
    default=None,
    type=None,
)
DEFAULT = Opt(
    name="default",
    metavar="DEFAULT",
    help="Toggle setting to default",
    default=False,
    type=None,
)

# Sub-command configuration: give them a name, help text, a tuple of ``Arg``
# instances and a tuple of ``Opts`` instances.
SubCommand = namedtuple("SubCommand", ["name", "help", "args", "opts"])
SUBCOMMANDS = (
    SubCommand(
        name="close-completed-transfers",
        help="Close all completed transfers.",
        args=(AM_API_KEY,),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="close-completed-ingests",
        help="Close all completed ingests.",
        args=(AM_API_KEY,),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="completed-transfers",
        help="Print all completed transfers.",
        args=(AM_API_KEY,),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="completed-ingests",
        help="Print all completed ingests.",
        args=(AM_API_KEY,),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="unapproved-transfers",
        help="Print all unapproved transfers.",
        args=(AM_API_KEY,),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="transferables",
        help="Print all transferable entities in the Storage Service.",
        args=(SS_API_KEY, TRANSFER_SOURCE),
        opts=(SS_USER_NAME, SS_URL, TRANSFER_PATH, OUTPUT_MODE),
    ),
    SubCommand(
        name="aips",
        help="Print all AIPs in the Storage Service.",
        args=(SS_API_KEY,),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="dips",
        help="Print all DIPs in the Storage Service.",
        args=(SS_API_KEY,),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="get-all-compressed-aips",
        help="Print all compressed AIPs in the Storage Service.",
        args=(SS_API_KEY,),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="aips2dips",
        help="Print all AIPs in the Storage Service along with their "
        "corresponding DIPs.",
        args=(SS_API_KEY,),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="aip2dips",
        help=("Print the AIP with AIP_UUID along with its corresponding DIP(s)."),
        args=(AIP_UUID, SS_API_KEY),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="download-dip",
        help="Download the DIP with DIP_UUID.",
        args=(DIP_UUID, SS_API_KEY),
        opts=(SS_USER_NAME, SS_URL, DIRECTORY, OUTPUT_MODE),
    ),
    SubCommand(
        name="download-aip",
        help="Download the AIP with AIP_UUID.",
        args=(AIP_UUID, SS_API_KEY),
        opts=(SS_USER_NAME, SS_URL, DIRECTORY, OUTPUT_MODE),
    ),
    SubCommand(
        name="delete-aip",
        help="Create deletion request for the AIP with AIP_UUID.",
        args=(
            AIP_UUID,
            SS_API_KEY,
            PIPELINE_UUID,
            EVENT_REASON,
            SS_USER_ID,
            SS_USER_EMAIL,
        ),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="get-pipelines",
        help="List (enabled) Pipelines known to the Storage Service.",
        args=(SS_API_KEY,),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="get-transfer-status",
        help="Print the status of a transfer if it exists in a transfer workflow.",
        args=(TRANSFER_UUID, AM_API_KEY),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="get-ingest-status",
        help="Print the status of an ingest if it exists in an ingest workflow.",
        args=(SIP_UUID, AM_API_KEY),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="get-processing-config",
        help="Print a processing configuration file given its name in Archivematica.",
        args=(AM_API_KEY,),
        opts=(PROCESSING_CONFIG, AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="approve-transfer",
        help="Approve a transfer in the Archivematica pipeline with a given UUID.",
        args=(TRANSFER_DIRECTORY, AM_API_KEY),
        opts=(TRANSFER_TYPE, AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="approve-partial-reingest",
        help="Approve a partial reingest using the SIP UUID.",
        args=(SIP_UUID, AM_API_KEY),
        opts=(AM_USER_NAME, AM_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="reingest-aip",
        help="Initiate the reingest of an AIP from the storage service with a given UUID.",
        args=(PIPELINE_UUID, AIP_UUID, SS_API_KEY),
        opts=(REINGEST_TYPE, PROCESSING_CONFIG, SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="get-package-details",
        help="Retrieve details about a package in the storage service with a given UUID.",
        args=(PACKAGE_UUID, SS_API_KEY),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="list-storage-locations",
        help="Retrieve a list of storage service locations.",
        args=(SS_API_KEY,),
        opts=(SS_USER_NAME, SS_URL, OUTPUT_MODE),
    ),
    SubCommand(
        name="create-package",
        help="Start and approve the processing of a transfer package.",
        args=(AM_API_KEY, TRANSFER_DIRECTORY),
        opts=(
            AM_USER_NAME,
            AM_URL,
            TRANSFER_SOURCE_OPT,
            TRANSFER_NAME,
            TRANSFER_TYPE,
            PROCESSING_CONFIG,
            OUTPUT_MODE,
        ),
    ),
    SubCommand(
        name="extract-file",
        help="Extract a file from a package in the storage service.",
        args=(SS_API_KEY, PACKAGE_UUID, RELATIVE_PATH),
        opts=(SS_USER_NAME, SS_URL, DIRECTORY, SAVEAS_FILENAME),
    ),
    SubCommand(
        name="extract-file-stream",
        help="Extract a file from a package in the storage service as a stream.",
        args=(SS_API_KEY, PACKAGE_UUID, RELATIVE_PATH),
        opts=(SS_USER_NAME, SS_URL),
    ),
    SubCommand(
        name="get-jobs",
        help="Retrieve a list of jobs ran for a unit (transfer or ingest).",
        args=(AM_API_KEY, UNIT_UUID),
        opts=(
            AM_USER_NAME,
            AM_URL,
            JOB_MICROSERVICE,
            JOB_LINK_UUID,
            JOB_NAME,
            OUTPUT_MODE,
        ),
    ),
    SubCommand(
        name="create-location",
        help="Create a new location in the Storage Service for a given space.",
        args=(
            PIPELINE_UUIDS,
            SPACE_UUID,
            LOCATION_PURPOSE,
            SPACE_RELATIVE_PATH,
            SS_API_KEY,
        ),
        opts=(SS_USER_NAME, SS_URL, LOCATION_DESCRIPTION, DEFAULT, OUTPUT_MODE),
    ),
)


def get_parser():
    """Parse arguments according to the ``SUBCOMMANDS`` configuration. Return
    an argparse ``Namespace`` instance representing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Archivematica Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--log-file", metavar="FILE", help="logfile", default=defaults.AMCLIENT_LOG_FILE
    )
    parser.add_argument(
        "--log-level",
        choices=["ERROR", "WARNING", "INFO", "DEBUG"],
        default=defaults.DEFAULT_LOG_LEVEL,
        help="Set the debugging output level.",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version="%(prog)s {}".format(version.version()),
    )
    subparsers = parser.add_subparsers(
        help="sub-command help", dest="subcommand", metavar="<command>"
    )
    for subcommand in SUBCOMMANDS:
        subparser = subparsers.add_parser(subcommand.name, help=subcommand.help)
        for arg in subcommand.args:
            subparser.add_argument(arg.name, help=arg.help, type=arg.type)
        for opt in subcommand.opts:
            subparser.add_argument(
                "--" + opt.name,
                metavar=opt.metavar,
                help=opt.help,
                default=opt.default,
                type=opt.type,
            )
    return parser
