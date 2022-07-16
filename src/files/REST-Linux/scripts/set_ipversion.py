# -*- coding:utf-8 -*-
"""
Function: set_ipversion.py moudle. This moudle mainly involves the
Setting an IP Version function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
import sys
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import REDFISH_STATUS_CODE_404
from scripts.common_function import REDFISH_STATUS_CODE_400
from scripts.common_function import UREST_STATUS_CODE_144
from scripts import common_function

FAILURE_MESS = 'Failure: some of the settings failed.\
 possible causes include the following: '


def setipversion_init(parser, parser_dict):
    """
    Function Description:initializing the Command for Setting an IP Version
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('setipversion', help='''set IP version''')
    sub_parser.add_argument('-M', dest='IPVersion',
                            type=str, required=True,
                            choices=['IPv4AndIPv6', 'IPv4', 'IPv6'],
                            help='''whether IPv4/IPv6 protocol is enabled''')
    parser_dict['setipversion'] = sub_parser

    return 'setipversion'


def package_request(args, payload):
    """
    Function Description:Encapsulate the request body.
    Parameter:args object:CLI command
    payload dict:redfish interface Parameter
    """
    oem = {}
    payload_inner_dic = {"IPVersion": args.IPVersion}
    oem[common_function.COMMON_KEY] = payload_inner_dic
    payload["Oem"] = oem


def part_err(ck_message):
    """
    Function Description:200 messages
    Parameter:ck_message dict:redfish interface value
    """
    idx = 0
    while idx < len(ck_message):
        check_info = ck_message[idx]['Message']
        message = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        message = message.replace("Oem/%s/" % common_function.COMMON_KEY, "")
        print('         %s' % message)
        idx += 1


def all_err(ck_message):
    """
    Function Description:400 messages
    Parameter:ck_message dict:redfish interface value
    """
    idx = 0
    while idx < len(ck_message):
        check_info = ck_message[idx]['Message']
        message = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        message = message.replace("Oem/%s/" % common_function.COMMON_KEY, "")
        if idx == 0:
            print('%s' % message)
        else:
            print('         %s' % message)
        idx += 1


def check_err_info(resp_ver, code_ipv):
    """
    Function Description:Determine whether all attributes are set successfully.
    Parameter:resp_ver dict:redfish Version value
    code_ipv int:redfish code
    """
    mess_ver = resp_ver.get("@Message.ExtendedInfo", "")
    len_mess = len(mess_ver)
    if len_mess != 0:
        ck_message = resp_ver["@Message.ExtendedInfo"]
    else:
        print('Success: successfully completed request')
        return None
    # Determine whether a permission problem occurs.
    if (ck_message[0]['MessageId'] ==
            "iBMC.1.0.PropertyModificationNeedPrivilege"
            or ck_message[0]['MessageId'] == "Base.1.0.InsufficientPrivilege"):
        print('Failure: you do not have the required permissions to perform '
              'this operation')
        return None

    # IP version error messages
    if code_ipv == REDFISH_STATUS_CODE_400:
        sys.stdout.write('Failure: ')
        all_err(ck_message)
        return None

    # Display 200 messages independently.
    if code_ipv == REDFISH_STATUS_CODE_200:
        print(FAILURE_MESS)
        part_err(ck_message)
        sys.exit(UREST_STATUS_CODE_144)

    return resp_ver


def set_version_info(members_uri, client, args):
    """
    Function Description:set ip version
    Parameter:client refishClient:class object
    args object:CLI command
    """
    # Encapsulate the request body.
    payload = {}
    package_request(args, payload)
    resp_ver = client.get_resource(members_uri)
    if resp_ver is None:
        return None
    if resp_ver['status_code'] != REDFISH_STATUS_CODE_200:
        if resp_ver['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return resp_ver

    resp_ver = client.set_resource(members_uri, payload)
    if resp_ver is None:
        return None
    if resp_ver['status_code'] == REDFISH_STATUS_CODE_200:
        check_err_info(resp_ver['resource'], resp_ver['status_code'])
    if resp_ver['status_code'] == REDFISH_STATUS_CODE_400:
        check_err_info(resp_ver['message']['error'], resp_ver['status_code'])

    return resp_ver


def get_port_collection(client, slotid, args):
    """
    Function Description:Query collection information.
    Parameter:client refishClient:class object
    slotid str:manager id
    args object:CLI command
    """
    url = "/redfish/v1/managers/%s/EthernetInterfaces" % slotid
    resp_ver = client.get_resource(url)
    if resp_ver is None:
        return None
    if resp_ver['status_code'] != REDFISH_STATUS_CODE_200:
        if resp_ver['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return resp_ver

    members_count = resp_ver['resource']["Members@odata.count"]
    if members_count == 0:
        print("no data available for the resource")
        return resp_ver
    # Set information.
    members_uri = resp_ver['resource']['Members'][0]["@odata.id"]
    resp_ver = set_version_info(members_uri, client, args)

    return resp_ver


def setipversion(client, args):
    """
    Function Description:Setting an IP Version
    Parameter:client refishClient:class object
    args object:CLI command
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    # Query collection information.
    ret = get_port_collection(client, slotid, args)
    return ret
