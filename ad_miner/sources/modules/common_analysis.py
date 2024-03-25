from ad_miner.sources.modules import logger
from ad_miner.sources.modules.utils import CONFIG_MAP

import re
import datetime
import time

obsolete_os_list = [
    "Windows XP",
    "Windows 7",
    "Windows 2000",
    "Windows 2003",
    "Windows 2008",
    "Windows 2008R2",
    "Windows 2012",
    "Windows 2012R2",
]


def getUserComputersCountPerDomain(requests_results):
    domains = requests_results["domains"]

    if domains is None:
        logger.print_error(" self.domains is None")
        return ["Domain is None", 0, 0]

    result = []
    users = requests_results["nb_enabled_accounts"]
    computers = requests_results["nb_computers"]

    for domain in domains:
        domain = domain[0]
        nb_user = len(
            [
                element
                for element in users
                if domain.upper() == element["domain"].upper()
            ]
        )  # Inclusion because of the icon. Space to check that it's the full domain name.
        nb_computer = len(
            [element for element in computers if element["domain"] == domain]
        )
        result.append([domain, nb_user, nb_computer])
    return result


def manageComputersOs(computer_list):
    if computer_list is None:
        return None
    all_os = {}
    computers_os_obsolete = []

    for line in computer_list:
        os = line["os"]
        if "windows" in os.lower():
            os = os.lower()
            os = os.replace("\xa0", " ")
            os = os.replace("®", "")
            os = os.replace(" server", "")
            os = os.replace(" storage", "")
            os = os.replace(" 2008 r2", " 2008R2")
            os = os.replace(" 2012 r2", " 2012R2")
            ver = re.match(r"^windows ([.a-zA-Z0-9]+)\s", os, re.M | re.I)
            if ver:
                os = "Windows " + ver.group(1).upper()
            else:
                os = os.replace("windows", "Windows")
        else:
            os = os

        # Cleaner way to do a try/except for dictionaries is to use get() :
        lastLogon = line.get("lastLogon", "Not specified")
        final_line = {
            "Domain": line["domain"],
            "name": line["name"],
            "Operating system": os,
            "Last logon in days": lastLogon,
        }

        # Stats for OS repartition
        def addToOS(key):
            if all_os.get(key):
                all_os[key] += 1
            else:
                all_os[key] = 1

        if "windows" in os.lower():
            addToOS(os)
        elif "linux" in os.lower() or "ubuntu" in os.lower():
            addToOS("Linux")
        elif "mac" in os.lower():
            addToOS("MacOS")
        elif "android" in os.lower():
            addToOS("Android")
        elif "ios" in os.lower():
            addToOS("iOS")
        else:
            addToOS("Other")

        if os in obsolete_os_list:
            computers_os_obsolete.append(final_line)
    return computers_os_obsolete, all_os


def rating_color(total_rating):
    # total_rating = rating(users, domains, computers, objects, arguments)
    dico_rating_color = {"on_premise": {}, "azure": {}}

    conf = CONFIG_MAP["requests"]
    for category_repartition in ["on_premise", "azure"]:
        for notation in total_rating[category_repartition]:
            for indicator in total_rating[category_repartition][notation]:
                if notation == 1:
                    color = "red"
                elif notation == 2:
                    color = "orange"
                elif notation == 3:
                    color = "yellow"
                elif notation == 4 or notation == 5:
                    color = "green"
                else:
                    color = "grey"

                # Check if control is disabled in config.json. If so, color = grey
                try:
                    disabled = conf.get(indicator) == "false"
                except KeyError:
                    disabled = False
                if disabled:
                    color = "grey"

                dico_rating_color[category_repartition][indicator] = color

    return dico_rating_color


# PERCENTAGE SUP FUNCTION
# If no presence argument : return criticity if > percentage
# If presence argument : return criticity if > percentage, criticity+1 if there at least one
def percentage_superior(req, base, criticity=1, percentage=0, presence=False):
    if req is None:
        return -1
    if base is None:
        return -1
    if len(base) == 0:
        return -1

    if len(base) and len(req) / len(base) > percentage:
        return criticity

    if presence:
        if len(req) > 0:
            return criticity + 1
    return 5


# PERCENTAGE INF FUNCTION
# return criticity if < percentage, criticity - 1 if < percentage/2
def percentage_inferior(req, base, criticity=1, percentage=0):
    if req is None:
        return -1
    if base is None:
        return -1
    if len(base) == 0:
        return -1

    if len(base) and len(req) / len(base) < percentage:
        return criticity

    if len(base) and len(req) / len(base) < percentage / 2:
        return criticity - 1

    return 5


# PRESENCE FUNCTION
# Return criticity if at least one, 5 if not
def presence_of(req, criticity=1, threshold=0):
    if req is None:
        return -1
    if len(req) > threshold:
        return criticity
    return 5


# TIME SINCE EXTRACT FUNCTION
# return criticity if time since > age, 5 if not
def time_since_extraction_date(req, extimestamp=0, age=90, criticity=1):
    if req is None:
        return -1

    year = int(extimestamp[0:4])
    month = int(extimestamp[4:6])
    day = int(extimestamp[6:8])
    date_time = datetime.datetime(year, month, day)
    extraction_date = time.mktime(date_time.timetuple())
    days_since = (extraction_date - req) / 86400

    if days_since > age:
        return criticity

    return 5


# TIME SINCE FUNCTION
# return criticity if time since > age, 5 if not
def time_since(req, age=90, criticity=1):  # req as days
    if req is None:
        return -1
    if req > age:
        return criticity

    return 5


# CONTAINS DA FUNCTION
# return criticity if at least one DA, 5 if not
def containsDAs(req, criticity=1):
    if req is None:
        return -1

    for object in req:
        if object.get("is_Domain_Admin"):
            if object["is_Domain_Admin"] == True:
                return criticity
        # if object.get("is_da"):
        #     if object["is_da"] == True:
        #         return criticity

    if len(req) > 0:
        return criticity + 1

    return 5
