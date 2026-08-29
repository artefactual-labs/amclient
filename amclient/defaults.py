# Defaults and constants for amclient.py and transfers.py
import re

DEF_AM_URL = "http://127.0.0.1:62080"
DEF_SS_URL = "http://127.0.0.1:62081"
DEF_USER_NAME = "test"

UUID_PATT = re.compile("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

UNDECODABLE = "UNABLE TO DECODE"
UNDEC_MSG = (
    "Unable to decode a transfer source component; giving up and"
    f" returning {UNDECODABLE}"
)

# Default log level.
DEFAULT_LOG_LEVEL = "INFO"

# Default Processing Configuration
DEFAULT_PROCESSING_CONFIG = "default"

# Default reingest type
DEFAULT_REINGEST_TYPE = "full"

# Default transfer type
DEFAULT_TRANSFER_TYPE = "standard"
