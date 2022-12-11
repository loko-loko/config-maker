from string import Template

from loguru import logger
from . import settings


#
# Globals
#

def signal_handler(signal: object, frame: object):
    logger.error("[sig-int] Signal Received, exit()")
    exit()


def get_hosts_from_input_file(input_file: str):
    """
    This function returns a list of hosts from an input file.
    """

    logger.debug(f"[hosts] Get hosts from file: {input_file}")

    if input_file.startswith("$BASE_PATH"):
        input_file = Template(input_file).substitute(
            BASE_PATH=settings.BASE_PATH
        )

    if not os.path.exists(input_file):
        logger.error(f"[hosts] Input host file not found: {input_file}")
        exit(1)

    try:
        with open(input_file, "r") as f:
            data = f.readlines()
        hosts = set([
            s.replace("\n", "").lower()
            for s in data
        ])

    except Exception as ex:
        logger.error(f"[hosts] Failed to get hosts from {input_file}: {ex}")
        exit(1)

    if not hosts:
        logger.error(f"[hosts] No hosts found from {input_file}")
        exit(1)

    return list(sorted(hosts))

