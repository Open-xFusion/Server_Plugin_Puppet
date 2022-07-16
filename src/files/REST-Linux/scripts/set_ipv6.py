# -*- coding:utf-8 -*-
"""
Function: set_ipv6.py moudle. This moudle mainly involves the
Setting IPv6 function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
import sys
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import REDFISH_STATUS_CODE_404
from scripts.common_function import REDFISH_STATUS_CODE_400
from scripts.common_function import UREST_STATUS_CODE_144

FAILURE_MESS = 'Failure: some of the settings failed.\
 possible causes include the following: '


def setipv6_init(parser, parser_dict):
    """
    Function Description:initializing the Command for Setting IPv6
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('setipv6',
                                   help='set IPv6 information of the iBMC '
                                        'network port')
    sub_parser.add_argument('-IP', dest='address', required=False,
                            help='''IPv6 address of the iBMC network port''')
    sub_parser.add_argument('-M', dest='addressorigin',
                            required=False, choices=['Static', 'DHCPv6'],
                            help='''how the IPv6 address of the iBMC
            network port is allocated''')
    sub_parser.add_argument('-G', dest='gateway', required=False,
                            help='gateway IPv6 address of the iBMC '
                                 'network port')
    sub_parser.add_argument('-L', dest='prefixlength', required=False,
                            type=int, help='IPv6 address prefix length of the '
                                           'iBMC network port')

    parser_dict['setipv6'] = sub_parser

    return 'setipv6'


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if args.address is None \
            and args.addressorigin is None \
            and args.gateway is None \
            and args.prefixlength is None:
        parser.error('at least one parameter must be specified')


def setipv6(client, args):
    """
    Function Description:Setting IPv6
    Parameter:client refishClient:class object
    args object:CLI command
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    # Query collection information.
    uri, resp = get_port_collection(client, slotid)
    if uri is None:
        return resp

    resp_ip6 = set_ipv6_addresses_info(uri, client, args)
    return resp_ip6


def set_ipv6_addresses_info(uri, client, args):
    """
    Function Description:set ipv6 addresses
    Parameter:uri str:redfish url
    client refishClient: class object
    args object:CLI command
    """
    resp_ip6 = client.get_resource(uri)
    if resp_ip6 is None:
        return None
    if resp_ip6['status_code'] != REDFISH_STATUS_CODE_200:
        if resp_ip6['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return resp_ip6

    payload = {}
    # Encapsulate the request body.
    if args.address is not None or args.prefixlength is not None \
            or args.addressorigin is not None:
        ip_addrresses = [{}]
        if args.address is not None:
            ip_addrresses[0]['Address'] = args.address
        if args.prefixlength is not None:
            ip_addrresses[0]['PrefixLength'] = args.prefixlength
        if args.addressorigin is not None:
            ip_addrresses[0]['AddressOrigin'] = args.addressorigin
        payload['IPv6Addresses'] = ip_addrresses
    if args.gateway is not None:
        payload['IPv6DefaultGateway'] = args.gateway
    resp_ip6 = client.set_resource(uri, payload)
    if resp_ip6 is None:
        return None
    if resp_ip6['status_code'] == REDFISH_STATUS_CODE_200:
        check_err_info(resp_ip6['resource'], resp_ip6['status_code'])
    if resp_ip6['status_code'] == REDFISH_STATUS_CODE_400:
        check_err_info(resp_ip6['message']['error'], resp_ip6['status_code'])

    return resp_ip6


def check_err_info(resp_ip6, code_ipv6):
    """
    Function Description:Determine whether all attributes are set successfully.
    Parameter:re_ipv6 dict:redfish ipv6 value
    code_ipv6 int:redfish code
    """
    mess_ipv6 = resp_ip6.get("@Message.ExtendedInfo", "")
    len_info = len(mess_ipv6)
    if len_info != 0:
        ipv6_message = resp_ip6["@Message.ExtendedInfo"]
    else:
        print('Success: successfully completed request')
        return None
    # Determine whether a permission problem occurs.
    if (ipv6_message[0]['MessageId'] ==
            "iBMC.1.0.PropertyModificationNeedPrivilege"
            or ipv6_message[0]['MessageId'] ==
            "Base.1.0.InsufficientPrivilege"):
        print('Failure: you do not have the required permissions to perform '
              'this operation')
        return None
    # ipv6 messages
    if code_ipv6 == REDFISH_STATUS_CODE_400:
        sys.stdout.write('Failure: ')
        all_err(ipv6_message)
        return None
    # Display 200 messages independently.
    if code_ipv6 == REDFISH_STATUS_CODE_200:
        print(FAILURE_MESS)
        part_err(ipv6_message)
        sys.exit(UREST_STATUS_CODE_144)

    return resp_ip6


def part_err(ipv6_message):
    """
    Function Description:200 messages
    Parameter:ipv6_message dict:redfish ipv6 value
    """
    idx = 0
    while idx < len(ipv6_message):
        check_info = ipv6_message[idx]['Message']
        message = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        message = message.replace("IPv6Addresses/0/", "")
        message = message.replace("IPv6Addresses/", "")
        print('         %s' % message)
        idx += 1


def all_err(ipv6_message):
    """
    Function Description:400 messages
    Parameter:ipv6_message dict:redfish ipv6 value
    """
    idx = 0
    while idx < len(ipv6_message):
        check_info = ipv6_message[idx]['Message']
        message = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        message = message.replace("IPv6Addresses/0/", "")
        message = message.replace("IPv6Addresses/", "")
        if idx == 0:
            print('%s' % message)
        else:
            print('         %s' % message)
        idx += 1


def get_port_collection(client, slotid):
    """
    Function Description:Query collection information.
    Parameter:client refishClient:class object
    slotid str:manager id
    """
    url = "/redfish/v1/managers/%s/EthernetInterfaces" % slotid
    resp_ip6 = client.get_resource(url)
    members_uri = None
    if resp_ip6 is None:
        return members_uri, None
    if resp_ip6['status_code'] != REDFISH_STATUS_CODE_200:
        if resp_ip6['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return members_uri, resp_ip6

    members_count = resp_ip6['resource']["Members@odata.count"]
    if members_count == 0:
        print("no data available for the resource")
        return members_uri, resp_ip6
    members_uri = resp_ip6['resource']['Members'][0]["@odata.id"]

    return members_uri, resp_ip6
