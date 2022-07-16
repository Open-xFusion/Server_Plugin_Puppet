# -*- coding:utf-8 -*-
"""
Function: get_ntp.py moudle. This moudle mainly involves the
Querying NTP Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import REDFISH_STATUS_CODE_404

NTP_FORMAT = "%-30s: %s"


def getntp_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Querying NTP Information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('getntp',
                                   help='get network time protocol information')
    parser_dict['getntp'] = sub_parser

    return 'getntp'


def getntp(client, _):
    """
    Function Description:Querying NTP Information
    Parameter:client refishClient:class object
    Return Value:resp dict:result of the redfish interface
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    url = "/redfish/v1/managers/%s/ntpservice" % slotid
    resp = client.get_resource(url)
    if resp is None:
        return None
    if resp['status_code'] == REDFISH_STATUS_CODE_200:
        ntpinfo = resp['resource']
        print(NTP_FORMAT % ("ServiceEnabled",
                            ntpinfo.get("ServiceEnabled", None)))
        print(NTP_FORMAT % ("PreferredNtpServer",
                            ntpinfo.get("PreferredNtpServer", None)))
        print(NTP_FORMAT % ("AlternateNtpServer",
                            ntpinfo.get("AlternateNtpServer", None)))
        print(NTP_FORMAT % ("NtpAddressOrigin",
                            ntpinfo.get("NtpAddressOrigin", None)))
        print(NTP_FORMAT % ("ServerAuthenticationEnabled",
                            ntpinfo.get("ServerAuthenticationEnabled", None)))
        print(NTP_FORMAT % ("MinPollingInterval",
                            ntpinfo.get("MinPollingInterval", None)))
        print(NTP_FORMAT % ("MaxPollingInterval",
                            ntpinfo.get("MaxPollingInterval", None)))
    elif resp['status_code'] == REDFISH_STATUS_CODE_404:
        print('Failure: resource was not found')
    return resp
