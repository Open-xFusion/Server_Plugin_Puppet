# -*- coding:utf-8 -*-
"""
Function: get_bmc_firmware.py moudle. This moudle mainly involves the
 Obtaining Out-of-Band Upgradeable Firmware function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
from scripts import common_function

PRINT_FORMAT = '%-10s%-2s%-20s'


def getbmcfirmware_init(parser, parser_list):
    """
    #=========================================================================
    #   @Description:  getbmcfirmware_init
    #
    #   @author:
    #   @Date:
    #=========================================================================
    """
    sub_parser = parser.add_parser('getfw',
                                   help='get firmware that can be upgraded')
    parser_list['getfw'] = sub_parser

    return 'getfw'


def get_bmc_firmware_message(client, str_bmc_firmware):
    """
    #=========================================================================
    #   @Description:  get_bmc_firmware_message
    #
    #   @author:
    #   @Date:
    #=========================================================================
    """
    resp_bmc_firmware = client.get_resource(str_bmc_firmware)
    if resp_bmc_firmware is None:
        return None
    if resp_bmc_firmware['status_code'] == 200:
        # Upgradeable firmware information
        if 'Name' in list(resp_bmc_firmware['resource'].keys()):
            print(PRINT_FORMAT % ('Name', ':',
                                  resp_bmc_firmware['resource']['Name']))
        if 'SoftwareId' in list(resp_bmc_firmware['resource'].keys()):
            print(PRINT_FORMAT % ('SoftwareId', ':',
                                  resp_bmc_firmware['resource']['SoftwareId']))

        oem = common_function.OEM_KEY
        resource = common_function.RESOURCE_KEY
        if oem in resp_bmc_firmware[resource]:
            oem_dict = resp_bmc_firmware[resource][oem]
            if common_function.COMMON_KEY in oem_dict:
                resp_inner_dic = oem_dict[common_function.COMMON_KEY]
                if 'PositionId' in resp_inner_dic:
                    print(PRINT_FORMAT % ('PositionId', ':',
                                          resp_inner_dic['PositionId']))

        if 'Version' in list(resp_bmc_firmware['resource'].keys()):
            print(PRINT_FORMAT % ('Version', ':',
                                  resp_bmc_firmware['resource']['Version']))
        if 'Updateable' in list(resp_bmc_firmware['resource'].keys()):
            print(PRINT_FORMAT % ('Updateable', ':',
                                  resp_bmc_firmware['resource']['Updateable']))
        if 'Status' in list(resp_bmc_firmware['resource'].keys()):
            if 'Health' in list(
                    resp_bmc_firmware['resource']['Status'].keys()):
                print(PRINT_FORMAT % ('Health', ':',
                                      resp_bmc_firmware['resource']['Status'][
                                          'Health']))
            if 'State' in list(resp_bmc_firmware['resource']['Status'].keys()):
                print(PRINT_FORMAT % ('State', ':',
                                      resp_bmc_firmware['resource']['Status'][
                                          'State']))
        print('-' * 40)
    return resp_bmc_firmware


def getbmcfirmware(client, _):
    """
    #=========================================================================
    #   @Description:  getbmcfirmware
    #
    #   @author:
    #   @Date:
    #=========================================================================
    """
    # Obtain upgradeable firmware collection resources.
    url = "/redfish/v1/UpdateService/FirmwareInventory"
    resp = client.get_resource(url)
    tmp_count = 0
    if resp is None:
        return None
    if resp['status_code'] == 404:
        print('Failure: resource was not found')
    elif resp['status_code'] == 200:
        firmware_count = len(resp['resource']['Members'])

        # Upgradeable firmware exists.
        if firmware_count > 0:
            print('-' * 40)
            while tmp_count < firmware_count:
                for key in resp['resource']['Members'][tmp_count]:
                    str_bmc_firmware = \
                        resp['resource']['Members'][tmp_count][key]

                    get_bmc_firmware_message(client, str_bmc_firmware)
                    tmp_count += 1
        # No upgradeable firmware exists.
        else:
            print('There is no firmware to be upgraded')

    return resp
