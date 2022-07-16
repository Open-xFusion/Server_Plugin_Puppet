# -*- coding:utf-8 -*-
"""
Function: set_dns.py moudle. This moudle mainly involves the
Setting DNS Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
import sys
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import REDFISH_STATUS_CODE_404
from scripts.common_function import REDFISH_STATUS_CODE_400
from scripts.common_function import UREST_STATUS_CODE_144
from scripts import common_function

FAILURE_MESS = 'failure: some of the settings failed.\
 possible causes include the following: '
HOSTNAME = 'specifies a host name for iBMC. value: a string of 1 \
to 64 characters setting, rule: the value can contain letters, digits, \
and hyphens (-), but cannot start or end with a hyphen'
DOMAIN = 'specifies a domain name for the server. value: \
a string of 0 to 67 characters setting rule: the value can \
contain letters, digits, and special characters including spaces'
DOMAINERR = 'invalid domain name. value: \
a string of 0 to 67 characters, setting rule: the value can \
contain letters, digits, and special characters including spaces'
DOMAINERR1 = '         invalid domain name. value: \
a string of 0 to 67 characters, setting rule: the value can \
contain letters, digits, and special characters including spaces'


def setdns_init(parser, parser_dict):
    """
    Function Description:initializing the Command for Setting DNS Information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('setdns', help='''set DNS information''')
    sub_parser.add_argument('-M', dest='DNSAddressOrigin',
                            type=str, required=False,
                            choices=['Static', 'IPv4', 'IPv6'],
                            help='''how DNS server information is obtained''')
    sub_parser.add_argument('-H', dest='HostName', type=str,
                            required=False, help=HOSTNAME)
    sub_parser.add_argument('-D', dest='Domain', type=str,
                            required=False, help=DOMAIN)
    sub_parser.add_argument('-PRE', dest='PreferredServer',
                            type=str, required=False,
                            help='specifies the IP address of the preferred '
                                 'DNS server')
    sub_parser.add_argument('-ALT', dest='AlternateServer',
                            type=str, required=False,
                            help='specifies the IP address of the alternate '
                                 'DNS server')
    parser_dict['setdns'] = sub_parser

    return 'setdns'


def package_request(args, payload, host_name, ip_server):
    """
    Function Description:Encapsulate the request body.
    Parameter:args object:CLI command
    payload dict:redfish interface Parameter
    host_name str:host name
    ip_server str:ip server
    """
    if args.HostName is not None:
        payload["HostName"] = args.HostName
        host_name = args.HostName
    if args.Domain is not None:
        payload["FQDN"] = ("%s.%s" % (host_name, args.Domain))
    # Set active and standby server addresses.
    len_server0 = len(ip_server[0])
    len_server1 = len(ip_server[1])
    if args.PreferredServer is not None or args.AlternateServer is not None:
        name_service = []
        if args.PreferredServer is not None:
            name_service.append(args.PreferredServer)
        elif args.PreferredServer is None and len_server0 != 0:
            name_service.append(ip_server[0])
        else:
            name_service.append("")
        if args.AlternateServer is not None:
            name_service.append(args.AlternateServer)
        elif args.AlternateServer is None and len_server1 != 0:
            name_service.append(ip_server[1])
        else:
            name_service.append("")
        payload["NameServers"] = name_service
    # Address mode
    if args.DNSAddressOrigin is not None:
        payload_inner_dic = {"DNSAddressOrigin": args.DNSAddressOrigin}
        oem = {common_function.COMMON_KEY: payload_inner_dic}
        payload["Oem"] = oem


def part_err(err_message):
    """
    Function Description:200 messages
    Parameter:err_message list:error message
    """
    idx = 0
    while idx < len(err_message):
        len_err = len(err_message[idx]['RelatedProperties'])
        if len_err != 0:
            if err_message[idx]['RelatedProperties'][0] \
                    == '#/FQDN':
                print(DOMAINERR1)
                idx += 1
                continue
        check_info = err_message[idx]['Message']
        message = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        message = message.replace("Oem/%s/" % common_function.COMMON_KEY, "")
        message = message.replace("NameServers/0", "PreferredServer")
        message = message.replace("NameServers/1", "AlternateServer")
        print('         %s' % message)
        idx += 1


def all_err(err_message):
    """
    Function Description:400 messages
    Parameter:err_message list:error message
    """
    idx = 0
    while idx < len(err_message):
        len_err = len(err_message[idx]['RelatedProperties'])
        if len_err != 0:
            if err_message[idx]['RelatedProperties'][0] \
                    == "#/FQDN":
                if idx == 0:
                    print(DOMAINERR)
                else:
                    print(DOMAINERR1)
                idx += 1
                continue
        check_info = err_message[idx]['Message']
        message = "%s%s" % \
                  (check_info[0].lower(), check_info[1:len(check_info) - 1])
        message = message.replace("Oem/%s/" % common_function.COMMON_KEY, "")
        message = message.replace("NameServers/0", "PreferredServer")
        message = message.replace("NameServers/1", "AlternateServer")
        if idx == 0:
            print('%s' % message)
        else:
            print('         %s' % message)
        idx += 1


def check_err_info(resp_dns, code_dns):
    """
    Function Description:Determine whether all attributes are set successfully.
    Parameter:resp_dns dict:redfish interface value
    code_dns int:redfish interface code
    """
    mess = resp_dns.get("@Message.ExtendedInfo", "")
    len_mess = len(mess)
    if len_mess != 0:
        err_message = resp_dns["@Message.ExtendedInfo"]
    else:
        print('Success: successfully completed request')
        return None
    # Determine whether a permission problem occurs.
    if err_message[0]['MessageId'] == \
            "iBMC.1.0.PropertyModificationNeedPrivilege":
        print('Failure: you do not have the required permissions to perform '
              'this operation')
        return None
    # DNS error message
    if code_dns == REDFISH_STATUS_CODE_400:
        sys.stdout.write('Failure: ')
        all_err(err_message)
        return None
    # Independent display of 200 messages
    if code_dns == REDFISH_STATUS_CODE_200:
        print(FAILURE_MESS)
        part_err(err_message)
        sys.exit(UREST_STATUS_CODE_144)

    return resp_dns


def set_dns_info(members_uri, client, args):
    """
    Function Description:Set DNS information.
    Parameter:members_uri str:Members url
    client refishClient: class object
    args object:CLI command
    """
    resp_dns = client.get_resource(members_uri)
    if resp_dns is None:
        return None
    if resp_dns['status_code'] != REDFISH_STATUS_CODE_200:
        if resp_dns['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return resp_dns
    host_name = resp_dns['resource']['HostName']
    name_service = resp_dns['resource']['NameServers']
    # Encapsulate the request body.
    payload = {}
    package_request(args, payload, host_name, name_service)
    resp_dns = client.set_resource(members_uri, payload)
    if resp_dns is None:
        return None
    if resp_dns['status_code'] == REDFISH_STATUS_CODE_200:
        check_err_info(resp_dns['resource'], resp_dns['status_code'])
    if resp_dns['status_code'] == REDFISH_STATUS_CODE_400:
        check_err_info(resp_dns['message']['error'], resp_dns['status_code'])

    return resp_dns


def get_port_collection(client, slotid, args):
    """
    Function Description:Query collection information.
    Parameter:client refishClient:class object
    slotid str:manager id
    args object:CLI command
    """
    url = "/redfish/v1/managers/%s/EthernetInterfaces" % slotid
    resp_dns = client.get_resource(url)
    if resp_dns is None:
        return None
    if resp_dns['status_code'] != REDFISH_STATUS_CODE_200:
        if resp_dns['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return resp_dns
    members_count = resp_dns['resource']["Members@odata.count"]
    if members_count == 0:
        print("no data available for the resource")
        return resp_dns
    # Set DNS information.
    members_uri = resp_dns['resource']['Members'][0]["@odata.id"]
    resp_dns = set_dns_info(members_uri, client, args)
    return resp_dns


def setdns(client, args):
    """
    Function Description:Setting DNS Information
    Parameter:client refishClient:class object
    args object:CLI command
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    # Query collection information.
    ret = get_port_collection(client, slotid, args)
    return ret


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if args.DNSAddressOrigin is None and args.HostName is None \
            and args.Domain is None and args.PreferredServer is None \
            and args.AlternateServer is None:
        parser.error('at least one parameter must be specified')
