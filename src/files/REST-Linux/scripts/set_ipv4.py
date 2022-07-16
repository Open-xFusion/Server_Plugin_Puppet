# -*- coding:utf-8 -*-
"""
Function: set_ipv4.py moudle. This moudle mainly involves the
Setting IPv4 function.
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


def setipv4_init(parser, parser_dict):
    """
    Function Description:initializing the Command for Setting IPv4
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('setipv4',
                                   help='set IPv4 information of the iBMC '
                                        'network port')
    sub_parser.add_argument('-IP', dest='address', required=False,
                            help='''IPv4 address of the iBMC network port''')
    sub_parser.add_argument('-M', dest='addressorigin', required=False,
                            choices=['Static', 'DHCP'],
                            help='''how the IPv4 address of the iBMC
                            network port is allocated''')
    sub_parser.add_argument('-G', dest='gateway', required=False,
                            help='''gateway IPv4 address of the
                            iBMC network port''')
    sub_parser.add_argument('-MASK', dest='subnetmask', required=False,
                            help='''subnet mask of the iBMC network port''')

    parser_dict['setipv4'] = sub_parser

    return 'setipv4'


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if args.address is None \
            and args.addressorigin is None \
            and args.gateway is None \
            and args.subnetmask is None:
        parser.error('at least one parameter must be specified')


def setipv4(client, args):
    """
    Function Description:Setting IPv4
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

    re_ipv4 = set_ipv4_addresses_info(uri, client, args)
    return re_ipv4


def set_ipv4_addresses_info(uri, client, args):
    """
    Function Description:set ipv4 addresses
    Parameter:uri str:redfish url
    client refishClient: class object
    args object:CLI command
    """
    re_ipv4 = client.get_resource(uri)
    if re_ipv4 is None:
        return None
    if re_ipv4['status_code'] != REDFISH_STATUS_CODE_200:
        if re_ipv4['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return re_ipv4

    # Encapsulate the request body.
    payload = {'IPv4Addresses': [{}]}
    if args.address is not None:
        payload['IPv4Addresses'][0]['Address'] = args.address
    if args.subnetmask is not None:
        payload['IPv4Addresses'][0]['SubnetMask'] = args.subnetmask
    if args.gateway is not None:
        payload['IPv4Addresses'][0]['Gateway'] = args.gateway
    if args.addressorigin is not None:
        payload['IPv4Addresses'][0]['AddressOrigin'] = args.addressorigin
    # Set
    re_ipv4 = client.set_resource(uri, payload)
    if re_ipv4 is None:
        return None
    if re_ipv4['status_code'] == REDFISH_STATUS_CODE_200:
        check_err_info(re_ipv4['resource'], re_ipv4['status_code'])
    if re_ipv4['status_code'] == REDFISH_STATUS_CODE_400:
        check_err_info(re_ipv4['message']['error'], re_ipv4['status_code'])

    return re_ipv4


def check_err_info(re_ipv4, code_ipv4):
    """
    Function Description:Determine whether all attributes are set successfully.
    Parameter:re_ipv4 dict:redfish ipv4 value
    code_ipv4 int:redfish code
    """
    mess_ipv4 = re_ipv4.get("@Message.ExtendedInfo", "")
    len_ipv4 = len(mess_ipv4)
    if len_ipv4 != 0:
        ipv4_message = re_ipv4["@Message.ExtendedInfo"]
    else:
        print('Success: successfully completed request')
        return None
    # Determine whether a permission problem occurs.
    if (ipv4_message[0]['MessageId'] ==
            "iBMC.1.0.PropertyModificationNeedPrivilege"
            or
            ipv4_message[0]['MessageId'] == "Base.1.0.InsufficientPrivilege"):
        print('Failure: you do not have the required permissions to perform '
              'this operation')
        return None
    # Display 400 messages independently.
    if code_ipv4 == REDFISH_STATUS_CODE_400:
        sys.stdout.write('Failure: ')
        all_err(ipv4_message)
        return None
    # Display 200 messages independently.
    if code_ipv4 == REDFISH_STATUS_CODE_200:
        print(FAILURE_MESS)
        part_err(ipv4_message)
        sys.exit(UREST_STATUS_CODE_144)
    return None


def part_err(ipv4_message):
    """
    Function Description:200 messages
    Parameter:ipv4_message dict:redfish ipv4 value
    """
    idx = 0
    while idx < len(ipv4_message):
        check_info = ipv4_message[idx]['Message']
        msge_ip = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        msge_ip = msge_ip.replace("IPv4Addresses/0/", "")
        msge_ip = msge_ip.replace("IPv4Addresses/", "")
        print('         %s' % msge_ip)
        idx += 1


def all_err(ipv4_message):
    """
    Function Description:400 messages
    Parameter:ipv4_message dict:redfish ipv4 value
    """
    idx = 0
    while idx < len(ipv4_message):
        check_info = ipv4_message[idx]['Message']
        msge_ip = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        msge_ip = msge_ip.replace("IPv4Addresses/0/", "")
        msge_ip = msge_ip.replace("IPv4Addresses/", "")
        if idx == 0:
            print('%s' % msge_ip)
        else:
            print('         %s' % msge_ip)
        idx += 1


def get_port_collection(client, slotid):
    """
    Function Description:Query collection information.
    Parameter:client refishClient:class object
    slotid str:manager_id
    """
    url = "/redfish/v1/managers/%s/EthernetInterfaces" % slotid
    re_ipv4 = client.get_resource(url)
    members_uri = None
    if re_ipv4 is None:
        return members_uri, None
    if re_ipv4['status_code'] != REDFISH_STATUS_CODE_200:
        if re_ipv4['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return members_uri, re_ipv4

    members_count = re_ipv4['resource']["Members@odata.count"]
    if members_count == 0:
        print("no data available for the resource")
        return members_uri, re_ipv4
    members_uri = re_ipv4['resource']['Members'][0]["@odata.id"]

    return members_uri, re_ipv4
