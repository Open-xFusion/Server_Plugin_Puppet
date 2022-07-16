# -*- coding:utf-8 -*-
"""
Function: get_drive_info.py moudle. This moudle mainly involves the
Querying Physical Disk Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
import sys

from pip._vendor.distlib.compat import raw_input
from scripts.common_function import INPUT_INFO
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import REDFISH_STATUS_CODE_404
from scripts.common_function import UREST_STATUS_CODE_148
from scripts.common_function import UREST_STATUS_CODE_2
from scripts import common_function

PF = '{0:40}: {1}'
PF1 = '{0}{1:32}: {2}'
PF2 = '{0}{1:36}: {2}'


def getdriveinfo_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Querying Physical Disk Information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('getpdisk',
                                   help='''get physical disk information''')
    sub_parser.add_argument('-I', dest='driveid',
                            type=int, required=False,
                            help='''physical disk ID''')
    sub_parser.add_argument('-PA', dest='PAGE',
                            choices=['Enabled', 'Disabled'],
                            required=False,
                            help='get physical disk '
                                 'information information paging display')
    parser_dict['getpdisk'] = sub_parser

    return 'getpdisk'


def print_sata_info(oem_info, key):
    """
    Function Description:Export SATA disk SMART information.
    Parameter:oem_info dict: redfish SATASmartInformation value
    key str: keyword
    """
    if oem_info is None:
        print(PF.format(key, None))
        return
    print('SATASmartInformation')
    print(PF2.format('    ', 'AttributeRevision',
                     oem_info['AttributeRevision']))
    print(PF2.format('    ', 'AttributeRevisionNumber',
                     oem_info['AttributeRevisionNumber']))
    for key_oem in oem_info:
        if key_oem == 'AttributeItemList':
            length = len(oem_info[key_oem])
            if length == 0:
                print(PF.format('    AttributeItemList', None))
                continue
            print('    AttributeItemList')
            index = 0
            while index < length:
                for key1 in oem_info[key_oem][index]:
                    value = oem_info[key_oem][index][key1]
                    print(PF1.format('        ', key1, value))
                index += 1
                if index != length:
                    print('%s%s' % ('        ', '-' * 33))
        elif key_oem not in ['AttributeRevision', 'AttributeRevisionNumber']:
            print(PF.format(key_oem, oem_info[key_oem]))


def print_drive_oem_info(oem_info):
    """
    Function Description:Export physical disk OEM information.
    Parameter:oem_info dict: redfish Oem value
    """
    for key in oem_info:
        if key == 'SpareforLogicalDrives':
            if oem_info[key]:
                volume_list = []
                get_vloume_list(oem_info[key], volume_list)
                print(PF.format(key, ','.join(volume_list)))
            else:
                print(PF.format(key, None))
        elif key == 'SASAddress':
            if oem_info[key]:
                print(PF.format(key, ','.join(oem_info[key])))
            else:
                print(PF.format(key, None))
        elif key not in ['Position', 'DriveID', 'NVMeSmartInformation',
                         'SASSmartInformation', 'SATASmartInformation']:
            print(PF.format(key, oem_info[key]))


def get_vloume_list(volumeinfo, volume_list):
    """
    Function Description:Obtain logical disk information.
    Parameter:volumeinfo list: Logical disk information
    volume_list list: Export the logical disk list.
    """
    length = len(volumeinfo)
    index = 0
    while index < length:
        url = volumeinfo[index]['@odata.id']
        obj = "%s-%s" % (url.split(r'/')[6], url.split(r'/')[8])
        volume_list.append(obj)
        index += 1


def print_smart_info(oem_info):
    """
    Function Description:Obtain SMART information.
    Parameter:oem_info dict: oem information
    """
    if oem_info.get('SASSmartInformation') is not None:
        print('SASSmartInformation')
        for key in oem_info['SASSmartInformation']:
            print(
                PF2.format('    ', key, oem_info['SASSmartInformation'][key]))

    if oem_info.get('SATASmartInformation') is not None:
        print_sata_info(oem_info['SATASmartInformation'],
                        'SATASmartInformation')

    if oem_info.get('NVMeSmartInformation') is not None:
        print('NVMeSmartInformation')
        for key in oem_info['NVMeSmartInformation']:
            print(
                PF2.format('    ', key, oem_info['NVMeSmartInformation'][key]))


def get_drive_info(client, drive_uri, flag):
    """
    Function Description:Obtain physical disk information.
    Parameter:client refishClient: class object
    drive_uri str: Logical disk redfish url
    flag int: The [-] flag is displayed.
    """
    drive_resp = client.get_resource(drive_uri)
    if drive_resp is None or drive_resp['status_code'] \
            != REDFISH_STATUS_CODE_200:
        return drive_resp

    drive_info = drive_resp['resource']
    oem_info = common_function.get_vendor_value(drive_resp)
    if flag == 0:
        print('-' * 50)
    # Display the ID. Name Container
    print(PF.format('Id', oem_info['DriveID']))
    print(PF.format('Name', drive_info['Name']))
    print(PF.format('Position', oem_info['Position']))
    print('')
    print('[Status]')
    print(PF.format('Health', drive_info['Status']['Health']))
    print(PF.format('State', drive_info['Status']['State']))
    print('')
    print(PF.format('Manufacturer', drive_info['Manufacturer']))
    print(PF.format('Model', drive_info['Model']))
    print(PF.format('Protocol', drive_info['Protocol']))
    print(PF.format('FailurePredicted', drive_info['FailurePredicted']))
    print(PF.format('CapacityBytes', drive_info['CapacityBytes']))
    print(PF.format('HotspareType', drive_info['HotspareType']))
    print(PF.format('IndicatorLED', drive_info['IndicatorLED']))
    print(PF.format('PredictedMediaLifeLeftPercent',
                    drive_info['PredictedMediaLifeLeftPercent']))
    print(PF.format('MediaType', drive_info['MediaType']))
    key_list = ['Id', '@odata.context', '@odata.id', '@odata.type', 'Location',
                'MediaType', 'Name', 'Status', 'Manufacturer', 'CapacityBytes',
                'Protocol', 'FailurePredicted', 'HotspareType', 'IndicatorLED',
                'Model', 'PredictedMediaLifeLeftPercent']
    for key in drive_info:
        if key == 'Oem':
            print_drive_oem_info(oem_info)
        elif key == 'Links':
            if drive_info[key]['Volumes']:
                volume_list = []
                get_vloume_list(drive_info[key]['Volumes'], volume_list)
                print(PF.format('Volumes', ','.join(volume_list)))
            else:
                print(PF.format('Volumes', None))
        elif key not in key_list:
            print(PF.format(key, drive_info[key]))
    print_smart_info(oem_info)
    print('-' * 50)
    return drive_resp


def check_drive_id_effective(client, drives_list, driveid, url, id_list):
    """
    Function Description:Check the physical disk URL.
    Parameter:client refishClient: class object
    drives_list list: Logical disk infos
    driveid str: Drive ID
    url list: Drive url
    id_list list: Drive ID list
    """
    index = 0
    while index < len(drives_list):
        resp = client.get_resource(drives_list[index])
        if resp is None or resp['status_code'] != REDFISH_STATUS_CODE_200:
            return False

        vendor_dict = common_function.get_vendor_value(resp)
        drive_id = vendor_dict['DriveID']
        id_list.append(str(drive_id))
        if driveid == drive_id:
            url.append(drives_list[index])
            return True
        index += 1
    return False


def get_drives_array(client, slotid, drives_list):
    """
    Function Description:Obtain the physical disk array.
    Parameter:client refishClient: class object
    slotid str: board ID.
    drives_list list: drives list
    """
    chassis_url = "/redfish/v1/Chassis/" + slotid
    resp = client.get_resource(chassis_url)
    if resp is None:
        return None
    if resp['status_code'] != REDFISH_STATUS_CODE_200:
        if resp['status_code'] == REDFISH_STATUS_CODE_404:
            print('Failure: resource was not found')
        return resp

    if resp['resource']['Links'].get('Drives') is None:
        return resp

    drive_array = resp['resource']['Links']['Drives']
    if drive_array:
        index = 0
        length = len(drive_array)
        while index < length:
            url = drive_array[index]['@odata.id']
            # SD cards and SSD cards are queried.
            if url.find('SD') > 0 or url.find('SSD') > 0:
                index += 1
                continue
            drives_list.append(url)
            index += 1
    return resp


def getdriveinfo(client, args):
    """
    Function Description:Querying Physical Disk Information
    Parameter:client refishClient: class object
    args object:CLI command
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    # Obtain the physical disk URL list.
    drives_list = []
    resp = get_drives_array(client, slotid, drives_list)
    if resp is None or resp['status_code'] != REDFISH_STATUS_CODE_200:
        return resp

    if not drives_list:
        print('Failure: resource was not found')
        return resp

    # Obtain information of all physical disks.
    if args.driveid is None:
        print_all_drives(args, client, drives_list)
    # Obtain the information of a single physical resource.
    else:
        resp = print_driveid(args, client, drives_list)
    return resp


def print_driveid(args, client, drives_list):
    """
    Function Description:print Physical Disk Information
    Parameter:client refishClient: class object
    args object:CLI command
    drives_list list: drives list
    """
    url = []
    id_list = []
    ret = check_drive_id_effective(client, drives_list,
                                   args.driveid, url, id_list)
    len_url = len(url)
    if ret is True and len_url != 0:
        return get_drive_info(client, url[0], 0)
    print("the value of -I parameter is invalid, choose from "
          '<' + ','.join(id_list) + '>')
    sys.exit(UREST_STATUS_CODE_2)


def print_all_drives(args, client, drives_list):
    """
    Function Description:print Physical Disk Informations
    Parameter:client refishClient: class object
    args object:CLI command
    drives_list list: drives list
    """
    index = 0
    while index < len(drives_list):
        get_drive_info(client, drives_list[index], index)

        if args.PAGE == "Enabled":
            # Control the input.
            if len(drives_list) == 1:
                index += 1
                continue
            strtemp = raw_input(INPUT_INFO).strip()
            tmp = strtemp.replace('\r', '')
            if tmp == 'q':
                return
        index += 1
