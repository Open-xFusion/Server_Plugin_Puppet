# -*- coding:utf-8 -*-
"""
Function: get_storage.py moudle. This moudle mainly involves the
 querying Storage Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
import sys

from pip._vendor.distlib.compat import raw_input
from scripts.common_function import INPUT_INFO
from scripts.common_function import UREST_STATUS_CODE_2
from scripts import common_function

PF = '{0}{1:26}: {2}'
PF1 = '{0}{1:26}'
PF2 = '{0:30}: {1}'


def getstorage_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
     querying Storage Information.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('getraid',
                                   help='''get RAID information''')
    sub_parser.add_argument('-CI', dest='controllerid',
                            type=int, required=False,
                            help='''controller ID''')
    sub_parser.add_argument('-LI', dest='logicaldriveid',
                            type=int, required=False,
                            help='''virtual disk ID''')
    sub_parser.add_argument('-PA', dest='PAGE',
                            choices=['Enabled', 'Disabled'], required=False,
                            help='get RAID information '
                                 'information paging display')
    parser_dict['getraid'] = sub_parser

    return 'getraid'


def check_span_get_drive_list(client, span_info, all_list):
    """
    #==========================================================================
    #   @Method:  View the logical disk span, and obtain the physical disk list.
    #   @Param:   client：
    #             span_info: span object
    #             all_list: physical disk list
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    length = len(span_info)
    index = 0
    while index < length:
        drive_list = []
        get_drive_id_list(client, span_info[index]['Drives'],
                          drive_list, all_list)
        span_info[index]['Drives'] = drive_list
        index += 1


def get_drive_id_list(client, drive_info, drive_list, all_list):
    """
    #==========================================================================
    # @Method:  Obtain the physical disk list.
    # @Param:   client:
                RedfishClient object drive_info Physical disk URI collection
                drive_list:
                Collection of some physical disk IDs all_list Collection
                of all physical disk IDs
    # @Return:  resp
    # @author:
    #==========================================================================
    """
    if drive_info:
        index = 0
        drive_length = len(drive_info)
        while index < drive_length:
            url = drive_info[index]['@odata.id']
            drive_resp = client.get_resource(url)
            if drive_resp is None:
                index += 1
                continue
            if drive_resp['status_code'] == 200:
                resp_inner_dic = common_function.get_vendor_value(drive_resp)
                drive_id = str(resp_inner_dic['DriveID'])
                drive_list.append(drive_id)
                if all_list is not None:
                    all_list.append(drive_id)
            index += 1


def get_vloume_list(volumeinfo, volume_list):
    """
    #==========================================================================
    #   @Method:  Obtain the logical disk list.
    #   @Param:   volumeinfo Logical disk URI collection
    #             volume_list Logical disk list
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    if volumeinfo:
        length = len(volumeinfo)
        index = 0
        while index < length:
            url = volumeinfo[index]['@odata.id']
            obj = "%s-%s" % (url.split(r'/')[6], url.split(r'/')[8])
            volume_list.append(obj)
            index += 1


def print_volumes_oem(oem_info, str_null):
    """
    #==========================================================================
    #   @Method:  Export logical disk OEM information.
    #   @Param:   oem_info OEM attribute list
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    print(PF.format(str_null, 'DefaultReadPolicy',
                    oem_info['DefaultReadPolicy']))
    print(PF.format(str_null, 'DefaultWritePolicy',
                    oem_info['DefaultWritePolicy']))
    print(PF.format(str_null, 'DefaultCachePolicy',
                    oem_info['DefaultCachePolicy']))
    print(PF.format(str_null, 'CurrentReadPolicy',
                    oem_info['CurrentReadPolicy']))
    print(PF.format(str_null, 'CurrentWritePolicy',
                    oem_info['CurrentWritePolicy']))
    print(PF.format(str_null, 'CurrentCachePolicy',
                    oem_info['CurrentCachePolicy']))
    print(PF.format(str_null, 'AccessPolicy',
                    oem_info['AccessPolicy']))
    key_list = ['Spans', 'SpanNumber', 'NumDrivePerSpan', 'AccessPolicy',
                'DefaultReadPolicy', 'DefaultWritePolicy',
                'DefaultCachePolicy',
                'CurrentReadPolicy', 'CurrentWritePolicy',
                'CurrentCachePolicy']
    for key in oem_info:
        if key == 'AssociatedCacheCadeVolume':
            if oem_info[key]:
                volume_list = []
                get_vloume_list(oem_info[key], volume_list)
                print(PF.format(str_null, key, ','.join(volume_list)))
            else:
                print(PF.format(str_null, key, None))
        elif key not in key_list:
            print(PF.format(str_null, key, oem_info[key]))


def getvolumesinfo(client, volumes_uri, flag):
    """
    #==========================================================================
    #   @Method:  Export logical disk information.
    #   @Param:  client: RedfishClient object
    #            volumes_uri Logical disk URI flag tag
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    volume_resp = client.get_resource(volumes_uri)
    if volume_resp is None or volume_resp['status_code'] != 200:
        return volume_resp

    volume_info = volume_resp['resource']
    if flag:
        str_null = '    '
    else:
        print('-' * 50)
        str_null = ''
    volumes = volumes_uri.split(r'/')[8]
    print(PF.format(str_null, 'Id', volumes[-1]))
    print(PF.format(str_null, 'Name', volume_info['Name']))
    print('')
    print(PF1.format(str_null, '[Status]'))
    print(PF.format(str_null, 'Health', volume_info['Status']['Health']))
    print(PF.format(str_null, 'State', volume_info['Status']['State']))
    print('')
    key_list = ['@odata.context', '@odata.id', '@odata.type', 'Links',
                'Id', 'Name', 'Status', 'Actions']
    for key in volume_info:
        if key == 'Oem':
            vendor_info = common_function.get_vendor_value(volume_resp)
            print_volumes_oem(vendor_info, str_null)

        elif key not in key_list:
            print(PF.format(str_null, key, volume_info[key]))

    all_list = []
    vendor_dict = common_function.get_vendor_value(volume_resp)
    check_span_get_drive_list(client, vendor_dict['Spans'],
                              all_list)
    print(PF.format(str_null, 'Drives', ','.join(all_list)))
    # Display span information.
    spannumber = vendor_dict['SpanNumber']
    if spannumber > 1:
        print(PF.format(str_null, 'SpanNumber', spannumber))
        print(PF.format(str_null, 'NumDrivePerSpan',
                        vendor_dict['NumDrivePerSpan']))
        print(PF1.format(str_null, '[Spans]'))
        index = 0
        while index < len(vendor_dict['Spans']):
            print(PF.format(str_null, 'SpanName',
                            vendor_dict['Spans'][index]['SpanName']))
            print(PF.format(str_null, 'Drives',
                            ','.join(vendor_dict['Spans'][index]['Drives'])))
            index += 1
    print(PF1.format(str_null, '-' * 50))
    return volume_resp


def controller_oem_info(oem_info):
    """
    #==========================================================================
    #   @Method:  Export OEM information.
    #   @Param:   oem_info OEM attribute list
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    print(PF2.format('SASAddress', oem_info['SASAddress']))
    print(PF2.format('ConfigurationVersion', oem_info['ConfigurationVersion']))
    print(PF2.format('MaintainPDFailHistory',
                     oem_info['MaintainPDFailHistory']))
    print(PF2.format('CopyBackState', oem_info['CopyBackState']))
    print(PF2.format('SmarterCopyBackState', oem_info['SmarterCopyBackState']))
    print(PF2.format('JBODState', oem_info['JBODState']))
    print(PF2.format('MinStripeSizeBytes', oem_info['MinStripeSizeBytes']))
    print(PF2.format('MaxStripeSizeBytes', oem_info['MaxStripeSizeBytes']))

    key_list = ['PHYStatus', 'SASAddress', 'ConfigurationVersion',
                'AssociatedCard',
                'MaintainPDFailHistory', 'CopyBackState',
                'SmarterCopyBackState',
                'JBODState', 'DDRECCCount', 'MinStripeSizeBytes',
                'MaxStripeSizeBytes', 'CapacitanceStatus']
    for key in oem_info:
        if key == 'SupportedRAIDLevels':
            if oem_info[key]:
                print(PF2.format(key, ','.join(oem_info[key])))
            else:
                print(PF2.format(key, None))

        elif key == 'DriverInfo':
            print(PF2.format('DriverName',
                             oem_info['DriverInfo']['DriverName']))
            print(PF2.format('DriverVersion',
                             oem_info['DriverInfo']['DriverVersion']))
        elif key not in key_list:
            print(PF2.format(key, oem_info[key]))

    print(PF2.format('DDRECCCount', oem_info['DDRECCCount']))
    print('')
    if oem_info['CapacitanceStatus']:
        print('[CapacitanceStatus]')
        print(PF2.format('Health', oem_info['CapacitanceStatus']['Health']))
        print(PF2.format('State', oem_info['CapacitanceStatus']['State']))
    else:
        print(PF2.format('[CapacitanceStatus]', None))
    print('')


def print_ctrl_info(controller):
    """
    #==========================================================================
    #   @Method:  Export controller information.
    #   @Param:   controller controller dictionary
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    key_list = ['@odata.id', 'MemberId', 'Description', 'Name', 'Status',
                'SpeedGbps', 'FirmwareVersion', 'Manufacturer', 'Model']
    for key in controller:
        if key == 'SupportedDeviceProtocols':
            if controller[key]:
                print(PF2.format(key, ','.join(controller[key])))
            else:
                print(PF2.format(key, None))
        elif key == 'Oem':
            controller_oem_info(controller['Oem'][common_function.COMMON_KEY])
        elif key not in key_list:
            print(PF2.format(key, controller[key]))


# Obtain controller information.
def getcontrollerinfo(client, controller_uri, flag, page_ctl):
    """
    Function Description:Obtain the controller information
    Parameter:client refishClient: class object
    controller_uri str:controller URL
    flag int：Members index
    page_ctl str: Pagination flag
    Modify: 2019.5.17 the pagination interaction method is optimized.
    Return Value: result of the redfish interface
    """
    ctrl_resp = client.get_resource(controller_uri)
    # If the required information is not obtained successfully,
    # the returned value is None.
    if ctrl_resp is None or ctrl_resp['status_code'] != 200:
        return ctrl_resp

    show_info(controller_uri, ctrl_resp, flag)
    # Export logical disk information.
    volumes_uri = ctrl_resp['resource']['Volumes']['@odata.id']
    volumes_resp = client.get_resource(volumes_uri)
    if volumes_resp is None or volumes_resp['status_code'] != 200:
        return volumes_resp

    if volumes_resp['resource']['Members']:
        volumes_length = len(volumes_resp['resource']['Members'])
        print('Volumes')
        index = 0
        while index < volumes_length:
            volumes_index = volumes_resp['resource']['Members'][index]
            volumes_url = volumes_index['@odata.id']
            getvolumesinfo(client, volumes_url, True)
            if page_ctl == "Enabled":
                if volumes_length == 1:
                    index += 1
                    continue
                strtemp = raw_input(INPUT_INFO).strip()
                tmp = strtemp.replace('\r', '')
                if tmp == 'q':
                    return ctrl_resp
            index += 1
    else:
        print(PF2.format('Volumes', None))

    show_drivers(client, ctrl_resp)
    return ctrl_resp


def show_drivers(client, ctrl_resp):
    """
    功能描述：展示虚拟磁盘管理的驱动器列表
    参数：client (RedfishClient)
        ctrl_resp （dict）: 通过url 获取到的redfish接口返回来的结果
    返回值：None
    异常描述：None
    修改:None
    """
    if ctrl_resp['resource']['Drives']:
        drive_list = []
        get_drive_id_list(client, ctrl_resp['resource']['Drives'],
                          drive_list, None)
        print(PF2.format('Drives', ','.join(drive_list)))
    else:
        print(PF2.format('Drives', None))
    print('-' * 60)


def show_info(controller_uri, ctrl_resp, flag):
    """
    Function Description:Displaying ctrl_resp Information to the Console
    Parameter:controller_uri (str):url
    ctrl_resp dict: result returned by the Redfish interface
    obtained through the URL
    flag int：Members index
    Modify: 2020.03.30 An error is reported when the
    DNS domain name is set in in-band mode.
    2020.06.18 When an inband session fails to be created,
    a message is displayed, prompting users to run
    the urest outband command.
    Return Value: result of the redfish interface
    """
    controller = ctrl_resp['resource']['StorageControllers'][0]
    # Export controller information.
    storage = controller_uri.split(r'/')[6]
    if flag == 0:
        print('-' * 60)
    print(PF2.format('Id', storage[-1]))
    print(PF2.format('Name', controller['Name']))
    print('')
    print('[Status]')
    print(PF2.format('Health', controller['Status']['Health']))
    print(PF2.format('State', controller['Status']['State']))
    print('')
    print(PF2.format('SpeedGbps', controller['SpeedGbps']))
    print(PF2.format('FirmwareVersion', controller['FirmwareVersion']))
    print(PF2.format('Manufacturer', controller['Manufacturer']))
    print(PF2.format('Model', controller['Model']))
    print_ctrl_info(controller)


def get_storage_info(args, resp, client):
    """
    Function Description:Obtain complete storage information.
    Parameter:client refishClient: class object
    resp dict:information about system collection resources
    args object:CLI command
    Modify: 2019.5.17 the pagination interaction method is optimized.
    Return Value: resp dict: result of the redfish interface
    """
    # No storage device exists in the environment.
    if not resp['resource']['Members']:
        print('Failure: resource was not found')
        return resp

    # RAID controller information
    storage_array = resp['resource']['Members']
    index = 0
    array_len = len(storage_array)

    while index < array_len:
        # Update controller information.
        url = resp['resource']['Members'][index]['@odata.id']

        # Filter the SD controller environment.
        if url.find("RAIDStorage") > 0:
            getcontrollerinfo(client, url, index, args.PAGE)

            if args.PAGE == "Enabled":
                if array_len == 1:
                    index += 1
                    continue
                strtemp = raw_input(INPUT_INFO).strip()
                tmp = strtemp.replace('\r', '')
                if tmp == 'q':
                    sys.exit(0)
        index += 1
    return resp


def get_specify_volume_info(args, client, systems, raidstorage):
    """
    #==========================================================================
    #   @Method:  Obtain specified logical disk information.
    #   @Param:   client, RedfishClient object,
                  slotid: environment slot information
    #   @Return:  resp
    #   @author:
    #==========================================================================
    """
    raid_url = systems + raidstorage + str(args.controllerid)
    resp = client.get_resource(raid_url)
    if resp is None:
        return resp

    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print("Failure: the value of -CI parameter is invalid")
            sys.exit(UREST_STATUS_CODE_2)

        return resp

    volumes = "/volumes/logicaldrive" + str(args.logicaldriveid)
    url = systems + raidstorage + str(args.controllerid) + volumes
    resp = getvolumesinfo(client, url, False)
    if resp is None:
        return resp

    if resp['status_code'] == 404:
        print("Failure: the value of -LI parameter is invalid")
        sys.exit(UREST_STATUS_CODE_2)

    return resp


def get_specify_contrl_info(client, url, page):
    """
    Function Description:Obtain specified controller information.
    Parameter:client refishClient: class object
    url str:specified URL
    page str:Pagination flag
    Modify: 2018.11.30 getcontrollerinfo（）adds the fourth parameter page.
    Return Value: resp dict:result of the redfish interface
    """
    resp = getcontrollerinfo(client, url, 0, page)
    if resp is None:
        return resp

    if resp['status_code'] == 404:
        # No RAID controller exists in the environment.
        print("Failure: the value of -CI parameter is invalid")
        sys.exit(UREST_STATUS_CODE_2)

    return resp


def check_storages(client, systems):
    """
    #=================================================================
    #   @Method:  Check before the configuration.
    #   @Param:   parser, major command argparser
    #             parser_list, save subcommand parser list
    #   @Return:
    #   @author:
    #=================================================================
    """
    url = systems + "/Storages"
    resp = client.get_resource(url)
    if resp is None:
        return None
    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
    # Check whether the controller URL exists and
    # whether the version is an earlier version.
    else:
        find_raidstorage(resp)
    return resp


def find_raidstorage(resp):
    """
    功能描述：打印 请求结果
    参数：resp (dict):redfish 接口返回值
    返回值：None
    异常描述：None
    修改：None
    """
    flag = False
    if resp['resource']['Members@odata.count'] == 0:
        print('Failure: resource was not found')
        return resp
    for i in range(0, len(resp['resource']['Members'])):
        url = resp['resource']['Members'][i]['@odata.id']
        if url.find("RAIDStorage") > 0:
            flag = True
            break
    if not flag:
        print('Failure: resource was not found')
        return resp


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    # To query logical disk information, you must enter the controller ID.
    if args.controllerid is None and args.logicaldriveid is not None:
        parser.error('the -CI parameter must be specified')


# Obtain storage information.
def getstorage(client, args):
    """
    #==========================================================================
    #   @Method:  Obtain storage information subcommand processing functions.
    #   @Param:   client, RedfishClient object
                  parser, subcommand argparser.
                  Export error messages when parameters are incorrect.
                  args, parameter list
    #   @Return:
    #   @author:
    #==========================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    # Determine whether a storage system exists.
    systems = "/redfish/v1/Systems/" + slotid
    resp = check_storages(client, systems)
    if resp is None:
        return None

    if resp['status_code'] != 200:
        return resp

    raidstorage = "/storages/raidstorage"
    if args.controllerid is not None and args.logicaldriveid is None:
        url = systems + raidstorage + str(args.controllerid)
        return get_specify_contrl_info(client, url, args.PAGE)

    # Query specified logical disk information.
    if args.controllerid is not None and args.logicaldriveid is not None:
        return get_specify_volume_info(args, client, systems, raidstorage)

    return get_storage_info(args, resp, client)
