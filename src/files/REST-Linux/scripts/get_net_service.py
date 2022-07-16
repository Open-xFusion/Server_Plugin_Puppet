# -*- coding:utf-8 -*-
"""
Function: get_net_service.py moudle. This moudle mainly involves the
Querying Network Service Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
import sys

from scripts import common_function

HELP_INFO = '''specify service information(State and Port value).'''
PRINT_STYLE = "%-35s:     %s"


def getnetservice_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Querying Network Service Information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('getnetsvc',
                                   help='''get network protocol information''')
    sub_parser.add_argument('-PRO', dest='Protocol',
                            choices=['HTTP', 'HTTPS', 'SNMP', 'VirtualMedia',
                                     'IPMI', 'SSH', 'KVMIP', 'SSDP', 'VNC'],
                            required=False, help=HELP_INFO)
    parser_dict['getnetsvc'] = sub_parser

    return 'getnetsvc'


def getnetservice(client, args):
    """
    Function Description:Querying Network Service Information
    Parameter:client refishClient:class object
    args object:CLI command
    Return Value: resp dict:result of the redfish interface
    """
    # Modify: 2018.8.29 clean up pylint alarms
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/managers/%s/networkprotocol" % slotid
    resp = client.get_resource(url)
    if resp is None or resp.get("status_code", "") == "":
        return None

    if resp['status_code'] == 200:
        print_result(args, resp)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')

    return resp


def print_result(args, resp):
    """
    Function Description:print result
    Parameter:resp dict:redfish value
    args object:CLI command
    """
    service_info = resp['resource']
    # Obtain the value of the Protocol attribute.
    key = args.Protocol
    flag = 0
    for oem_key in service_info:
        if oem_key == 'Oem':
            flag = 1
    if flag == 1:
        if common_function.get_vendor_value(resp) is None:
            print('Failure: the -PRO parameter is invalid')
            return

    if args.Protocol is not None:
        getspecifynetprop(resp, key)
        return
    getnetprop(service_info)


def getspecifynetprop(resp, key):
    """
    Function Description:Obtain subfunctions of
    specified network service attributes.
    Parameter:resp dict:redfish value
    key str:specified parameter
    """
    service_info = resp['resource']
    if service_info is None and key is None:
        sys.exit(127)

    state = None
    port = None
    # Specify the VNC to be queried and display information.
    if key == 'VNC':
        # Modify: 2017.8.21 The method of changing the
        # dictionary value is modified
        # Modify: 2020.06.24 提示信息修改
        if common_function.OEM_KEY in service_info:
            vendor_dict = common_function.get_vendor_value(resp)
            key_dict = vendor_dict.get(key)
            if key_dict:
                state = key_dict.get('ProtocolEnabled')
                port = key_dict.get('Port')
        print('')
        print('[%s]' % key)
    # If the service is null or the enabling status is null,
    # the service is not displayed.
    # Modify: 2017.8.21 The method of changing the dictionary value is modified
    elif service_info.get(key, '') == '' or service_info[key] is None or \
            service_info[key]['ProtocolEnabled'] is None:
        print('Failure: the -PRO parameter is invalid')
        return
    # Specify the non-OEM attribute to be queried and display information.
    else:
        print('')
        print('[%s]' % key)
        state = service_info[key]['ProtocolEnabled']
        port = service_info[key]['Port']
    print(PRINT_STYLE % ("State", state))
    print(PRINT_STYLE % ("Port", port))

    # Add other attributes in the SSDP protocol and display information.
    if key == 'SSDP':
        notifyttl = service_info[key]['NotifyTTL']
        notifyipv6scope = service_info[key]['NotifyIPv6Scope']
        notifymulticastintervalseconds = service_info[key][
            'NotifyMulticastIntervalSeconds']
        print(PRINT_STYLE % ("NotifyTTL", notifyttl))
        print(PRINT_STYLE % ("NotifyIPv6Scope", notifyipv6scope))
        print(PRINT_STYLE %
              ("NotifyMulticastIntervalSeconds",
               notifymulticastintervalseconds))


def getnetprop(service_info):
    """
    Function Description:Obtain network service attribute subfunctions.
    Parameter:service_info dict:redfish value
    """
    ket_list = ['@odata.context', '@odata.type', '@odata.id', 'Name',
                'HostName', 'FQDN', 'Id']
    if service_info is None:
        sys.exit(127)
    else:
        for key in service_info:
            if key in ket_list:
                continue

            # If the service is null, the service is not displayed.
            if service_info[key] is None:
                continue

            # OEM attribute VNC display
            if key == 'Oem':
                vnc_key = 'VNC'
                vendor_dict = service_info[key][common_function.COMMON_KEY]
                if vendor_dict is None or vendor_dict[vnc_key] is None:
                    continue
                print('')
                print('[%s]' % vnc_key)
                state = vendor_dict[vnc_key]['ProtocolEnabled']
                port = vendor_dict[vnc_key]['Port']
            else:
                state = service_info[key]['ProtocolEnabled']
                port = service_info[key]['Port']
                # If the enabling status and the port are null,
                # the service is not displayed.
                if (state is None) and (port is None):
                    continue
                print('')
                print('[%s]' % key)

            print(PRINT_STYLE % ("State", state))
            print(PRINT_STYLE % ("Port", port))

            # Add other SSDP attributes and display information.
            if key == 'SSDP':
                notifyttl = service_info[key]['NotifyTTL']
                notifyipv6scope = service_info[key]['NotifyIPv6Scope']
                notifymulticastintervalseconds = service_info[key][
                    'NotifyMulticastIntervalSeconds']
                print(PRINT_STYLE % ("NotifyTTL", notifyttl))
                print(PRINT_STYLE % ("NotifyIPv6Scope", notifyipv6scope))
                print(PRINT_STYLE %
                      ("NotifyMulticastIntervalSeconds",
                       notifymulticastintervalseconds))
