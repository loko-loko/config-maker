import re
import os
import sys
import csv
import html
from time import time
from string import Template

import shutil
import subprocess
from loguru import logger
from prettytable import PrettyTable

from configs import settings


# Load compiled regex
RE_INVENTORY_HOST = settings.RE_INVENTORY_HOST

#
# Globals
#

def signal_handler(signal: object, frame: object):
    logger.error("[sig-int] Signal Received, exit()")
    exit()


def get_hosts_from_input_file(input_file: str):
    """
    This function returns a list of hosts from an input file.

    >>> get_hosts_from_input_file(
    ...   input_file=settings.TEST_HOSTS_FILE_WITHOUT_DUPLICATES
    ... )
    ['server1', 'server2']
    >>> get_hosts_from_input_file(
    ...   input_file=settings.TEST_HOSTS_FILE_WITH_DUPLICATES
    ... )
    ['server1', 'server2', 'server3']
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
            for s in data if not RE_INVENTORY_HOST.search(s)
        ])

    except Exception as ex:
        logger.error(f"[hosts] Failed to get hosts from {input_file}: {ex}")
        exit(1)

    if not hosts:
        logger.error(f"[hosts] No hosts found from {input_file}")
        exit(1)

    return list(sorted(hosts))


def check_if_empty(data: dict, key: str, exclude: bool = False):
    """
    This function check if data key exist and return
    a Bool or a NoneType if exclude=True.

    >>> check_if_empty(
    ...   data=dict(a="a", b="b"),
    ...   key="a",
    ... )
    True
    >>> check_if_empty(
    ...   data=dict(a="a", b="b"),
    ...   key="c",
    ... )
    False
    >>> check_if_empty(
    ...   data=dict(a="a", b="b"),
    ...   key="c",
    ...   exclude=True,
    ... ) is None
    True
    """

    if exclude:
        return None

    return True if data.get(key) != None else False


def logger_setup(debug: bool = False):
    log_level = "DEBUG" if debug else "INFO"
    formatter="{time:YYYY/MM/DD HH:mm:ss}  {level:<7} {message}"
    logger.remove()
    logger.add(
        sys.stdout,
        level=log_level,
        colorize=True,
        format=formatter
    )


def convert_elapse_time(elapse_time: object):
    elapse_time_minutes = 0
    elapse_time_seconds = round((time() - elapse_time), 1)

    if elapse_time_seconds >= 60:
        elapse_time_minutes = int(elapse_time_seconds/60)
        elapse_time_seconds = round((elapse_time_seconds%60), 1)

    # convert time with zfill
    elapse_time_minutes = str(elapse_time_minutes).zfill(2)
    elapse_time_seconds = str(elapse_time_seconds).zfill(4)

    return f"{elapse_time_minutes}m{elapse_time_seconds}s"


def convert_size(size: int, unit: str = "B", round_float: int = 1):
    """
    This function convert size and return
    string with formatted size

    >>> convert_size(
    ...   size=1024,
    ... )
    '1.0 KB'
    >>> convert_size(
    ...   size=1024,
    ...   unit="MB"
    ... )
    '1.0 GB'
    """

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    unit_index = units.index(unit)
    if size < 1024:
        return "%(size)s %(unit)s" % dict(
            size=round(size, round_float),
            unit=units[unit_index]
        )
    return convert_size(
        size=float(size / 1024),
        unit=units[unit_index + 1]
    )


def camel_to_upper_snake(name: str):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).upper()


def create_tmp_path(tmp_path: str):
    """
    This function create a tmp directory
    """

    if os.path.exists(tmp_path):
        logger.debug(f"[tmp-path] Tmp path already exist: {tmp_path}")
        return

    try:
        logger.debug(f"[tmp-path] Create tmp path: {tmp_path}")
        os.makedirs(tmp_path)

    except Exception as ex:
        logger.error(f"[tmp-path] Problem to create tmp path {tmp_path}: {ex}")
        exit(1)


def remove_tmp_path(tmp_path: str):
    """
    This function remove tmp directory
    """

    # Clean tmp path
    logger.debug(f"[tmp-path] Remove tmp path: {tmp_path}")

    try:
        shutil.rmtree(tmp_path)
    except Exception as ex:
        logger.error(f"[tmp-path] Problem to remove tmp path {tmp_path}: {ex}")
        exit(1)


def get_data_to_collect(exclude_data_collect: str):

    # Get all data to collect from settings
    data_to_collect = list(settings.DATA_TO_COLLECT)

    if not exclude_data_collect:
        return data_to_collect

    # Exclude data to collect if --exclude-data-collect is used
    exclude_data = exclude_data_collect.split(",")

    for to_exclude in exclude_data:
        if to_exclude.lower() not in settings.DATA_TO_EXCLUDE:
            logger.error(f"[exclude] '{to_exclude}' not found. Choices: {settings.DATA_TO_EXCLUDE}")
            exit(2)

        if to_exclude in data_to_collect:
            data_to_collect.remove(to_exclude)

    return data_to_collect


def build_table(
    data: list,
    headers: list = None,
    align: str = "l",
    sort_by: str = None,
    sort_reverse: bool = False,
    to_html: bool = False,
    html_attributes: dict = {},
):
    # Generate index
    tab = PrettyTable()

    if not headers:
        headers = list(data[0].keys())

    tab.field_names = headers

    for row in data:
        # Add row
        tab.add_row(list(row.values()))

    # Format tab
    if align:
        tab.align = align

    if sort_by:
        tab.sortby = sort_by

    tab.reversesort = sort_reverse

    data = tab

    # Get html data
    if to_html:
        data = data.get_html_string(
            attributes=html_attributes
        )
        data = html.unescape(data)

    return data

#
# Decorators
#

def ssh_exception_check(resource: str):
    def decorator(method: object):
        def wrapper(ref):
            err_msg = (
                f"[ssh-collect] Problem to retrieve "
                f"{resource} on {ref.hostname}"
            )
            result = {}

            try:
                result = method(ref)
            except Exception as ex:
                ex_msg = str(ex)

                # NOTE: Display Exception message
                #       only if not null
                if ex_msg:
                    err_msg += f": {ex_msg}"

            if result == {}:
                logger.error(err_msg)

            return result
        return wrapper
    return decorator


def resource_collect_timer(resource: str):
    def decorator(method: object):
        def wrapper(ref):
            # Start time
            start_time = time()

            result = method(ref)

            if len(result) != 0:
                # End of script
                end_time = convert_elapse_time(
                    elapse_time=start_time
                )
                logger.info(
                    f"[resource] {resource} -> Collect "
                    f"done [Time:{end_time}]"
                )

            return result
        return wrapper
    return decorator

#
# Data Manipulation
#

def write_data_to_csv(
    data: list,
    output_file: str,
    display_suffix: bool = True,
    delimiter: str = settings.DEFAULT_CSV_DELIMITER,
    list_delimiter: str = settings.DEFAULT_CSV_LIST_DELIMITER,
):
    logger.info(f"[output] Write data to output file: {output_file}")

    # Get some parameters from settings
    suffix_delimiter = settings.CSV_VALUE_SUFFIX_DELIMITER
    suffix_types = settings.CSV_VALUE_TYPE_SUFFIX
    dict_value_delimiter = settings.CSV_DICT_VALUE_DELIMITER
    dict_items_delimiter = settings.CSV_DICT_ITEMS_DELIMITER

    # Build headers
    headers = []
    for key in data[0].keys():
        value_type = settings.ALL_DATA_TYPES.get(key)
        if not value_type:
            logger.error(f"[csv] Value type not found for key: {key}")
            exit(3)

        formatted_key = key
        # Add suffix if display_suffix=True
        if display_suffix:
            formatted_key = f"{key}{suffix_delimiter}{suffix_types[value_type]}"

        headers.append(formatted_key)

    with open(output_file, "w", encoding="UTF8", newline="") as of:

        writer = csv.DictWriter(
            of,
            fieldnames=headers,
            delimiter=delimiter,
            dialect=csv.excel
        )
        writer.writeheader()

        for row in data:
            formatted_row = {}
            for key, values in row.items():

                value_type = settings.ALL_DATA_TYPES[key]
                formatted_key = key

                # Add suffix if display_suffix=True
                if display_suffix:
                    formatted_key = f"{key}{suffix_delimiter}{suffix_types[value_type]}"

                formatted_values = values

                # Transform null value
                if values in [None, "", "None"]:
                    formatted_values = settings.DEFAULT_EMPTY_VALUE

                # Transform bool
                elif type(values) == bool:
                    formatted_values = settings.CSV_BOOL_MAP[values]

                # Transform list (+dict)
                elif type(values) == list:
                    formatted_values = values

                    # NOTE: If empty list set empty value
                    if not values:
                        formatted_values = [settings.DEFAULT_EMPTY_VALUE]

                    elif type(values[0]) == dict:
                        # NOTE: If empty dict set empty value
                        if not values[0]:
                            formatted_values = [settings.DEFAULT_EMPTY_VALUE]

                        else:
                            # Format value of dict type
                            formatted_values = []
                            for value in values:
                                formatted_values.append(
                                    dict_items_delimiter.join(
                                        [f"{k}{dict_value_delimiter}{v}" for k, v in value.items()]
                                    )
                                )

                    formatted_values = list_delimiter.join(formatted_values)

                # Update row with new data
                formatted_row[formatted_key] = formatted_values

            writer.writerow(formatted_row)


def load_csv_data(
    csv_file: str,
    delimiter: str = settings.DEFAULT_CSV_DELIMITER,
    list_delimiter: str = settings.DEFAULT_CSV_LIST_DELIMITER,
    transform_list: bool = True
):
    """
    This function load data from csv file

    >>> load_csv_data(
    ...   csv_file=settings.TEST_DATA_CSV_FILE
    ... )
    [{'a': 'b', 'b': ['c', 'd'], 'c': [{'d': 'e'}, {'g': 'h'}], 'd': 12.8, 'e': 3, 'f': True, 'g': None}]
    """

    logger.info(f"[csv] Load data from {csv_file}")

    # Get some parameters from settings
    suffix_delimiter = settings.CSV_VALUE_SUFFIX_DELIMITER
    suffix_types = settings.CSV_VALUE_TYPE_SUFFIX
    dict_value_delimiter = settings.CSV_DICT_VALUE_DELIMITER
    dict_items_delimiter = settings.CSV_DICT_ITEMS_DELIMITER

    # Reverse dict: v=k (ex: lst=list,bol=bool,...)
    suffix_types = {v: k for k, v in suffix_types.items()}

    data = []
    with open(csv_file, "r", encoding="UTF8", newline='') as f:
        raw_data = csv.DictReader(f, delimiter=delimiter, dialect=csv.excel)

        for row in raw_data:
            formatted_row = {}
            for key, values in row.items():
                value_suffix = key.split(suffix_delimiter)[-1]

                value_type = suffix_types.get(value_suffix)

                if not value_type:
                    logger.error(f"[csv] Value type not found for key: {key}")
                    exit(3)

                formatted_key = key.split(suffix_delimiter)[0]
                formatted_values = values

                # Transform list
                if transform_list and value_type == "list":

                    if values == settings.DEFAULT_EMPTY_VALUE:
                        formatted_values = []
                    else:
                        formatted_values = values.split(list_delimiter)

                # Transform dict
                elif transform_list and value_type == "dict":

                    if values == settings.DEFAULT_EMPTY_VALUE:
                        formatted_values = [dict()]
                    else:
                        formatted_values = []

                        # Transform value on list
                        splitted_values = values.split(list_delimiter)

                        for value in splitted_values:
                            formatted_value = {
                                v.split(dict_value_delimiter)[0]: v.split(dict_value_delimiter)[1]
                                for v in value.split(dict_items_delimiter)
                            }
                            formatted_values.append(formatted_value)

                # Transform empty value
                elif values == settings.DEFAULT_EMPTY_VALUE:
                    formatted_values = None

                # Transform bool
                elif value_type == "bool":
                    formatted_values = settings.CSV_CHOICE_MAP[values]

                # Transform int
                elif value_type == "int":
                    formatted_values = int(values)

                # Transform float
                elif value_type == "float":
                    formatted_values = round(float(values), 2)

                formatted_row[formatted_key] = formatted_values

            data.append(formatted_row)

    return data


def format_metrics_data(data: list):

    ignored_count = 0
    formatted_data = []

    for server in data:
        server_name = server['server_name']

        if server.get("anomalies") == None:
            ignored_count += 1
            logger.warning(f"[export-data] Anomalies not found for {server_name}. skip()")
            continue

        if "aliases_to_remove" in server["anomalies"]:
            ignored_count += 1
            logger.debug(
                f"[export-data] Ignore server with "
                f"'aliases_to_remove' anomaly: {server_name}"
            )
            continue

        new_server = {}

        for key, value in server.items():

            if key == "anomalies":
                value = list(set(
                    [settings.ANOMALIES_SHORT_MAP.get(a, a) for a in value]
                ))

            if type(value) == str and ".mousquetaires" in value:
                value = value.split(".")[0]

            elif value in ["", [], None]:
                value = settings.DEFAULT_EMPTY_VALUE

            elif type(value) == bool:
                value = settings.CSV_BOOL_MAP[value]

            elif type(value) == list:

                if value and type(value[0]) == dict:
                    continue

                value = "|".join(value)

            new_server[key] = value

        formatted_data.append(new_server)

    return formatted_data

#
# IP tools
#

def addr_ping(addr: str):
    logger.debug(f"[ping-check] Ping check on address: {addr}")
    cmd = subprocess.run(
        f"ping -c 1 -w 1 {addr}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return True if cmd.returncode == 0 else False


def addr_dmz_check(addr: str):
    logger.debug(f"[dmz-check] Check if address is DMZ: {addr}")
    if not addr:
        return False
    return True if "192.168" in addr else False


