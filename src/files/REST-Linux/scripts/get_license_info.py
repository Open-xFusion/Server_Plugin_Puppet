# -*- coding:utf-8 -*-
"""
Function: get_license_info.py moudle. This moudle mainly involves the
Querying the iBMC License Service Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2018-2020
"""
from scripts.common_function import REDFISH_STATUS_CODE_404
from scripts.common_function import REDFISH_STATUS_CODE_200


def getlicenseinfo_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Querying the iBMC License Service Information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('getlicenseinfo',
                                   help='''get license information''')

    parser_dict['getlicenseinfo'] = sub_parser

    return 'getlicenseinfo'


def getlicenseinfo(client, _):
    """
    Function Description:Querying the iBMC License Service Information
    Parameter:client refishClient:class object
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/LicenseService" % slotid
    resp = client.get_resource(url)

    if resp is None:
        return None

    if resp['status_code'] == REDFISH_STATUS_CODE_200:
        print_resource(resp['resource'])

    elif resp['status_code'] == REDFISH_STATUS_CODE_404:
        print('Failure: resource was not found')

    else:
        print("Failure: the request failed due to an internal service error")

    return resp


def recur_display(keyv, count):
    """
    Function Description:Handle license information display matter
    Parameter:keyv list/dict: response license information list or dict
    count int:indentation times
    """
    if isinstance(keyv, list):
        for lst in keyv:
            recur_display(lst, count)
    elif isinstance(keyv, dict):
        for dct in keyv:
            if not isinstance(keyv[dct], (list, dict)):
                print("%s%s:" % (" " * count * 2, str(dct)))
                print(keyv[dct])
            else:
                print("%s%s:" % (" " * count * 2, str(dct)))
                recur_display(keyv[dct], count + 1)
    else:
        print(" " * count * 2 + str(keyv))


def print_resource(info):
    """
    Function Description:print license information
    Parameter:info dict:response license infomation
    """
    print("%s%-2s%s" % ("Id", ":", info['Id']))
    print("%s%-2s%s" % ("Name", ":", info['Name']))
    print("%s%-2s%s,%s" %
          ("Capability", ":", info['Capability'][0], info['Capability'][1]))
    print("%s%-2s%s" % ("DeviceESN", ":", info['DeviceESN']))
    print("%s%-2s%s" % ("InstalledStatus", ":", info['InstalledStatus']))
    print("%s%-2s%s" % ("RevokeTicket", ":", info['RevokeTicket']))
    print("%s%-2s%s" % ("LicenseClass", ":", info['LicenseClass']))
    print("%s%-2s%s" % ("LicenseStatus", ":", info['LicenseStatus']))
    print("LicenseInfo:")
    recur_display(info['LicenseInfo'], 1)
    print("AlarmInfo:")
    recur_display(info['AlarmInfo'], 1)
