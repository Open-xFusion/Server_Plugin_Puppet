# -*- coding:utf-8 -*-
"""
Function: get_sp_hardware.py moudle. This moudle mainly involves the
 querying the Smart Provisioning Hardware Configuration File function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
from json import dumps
from os import path
from scripts import common_function

FORMAT = '%-30s: %s'

FAIL = "Failure: insufficient permission for the file or file name not " \
       "specified, perform this operation as system administrator/root, " \
       "or specify a file name"


def getsphardware_init(parser, parser_list):
    """
    #=====================================================================
    #   @Method:  SP query subcommand
    #   @Param:   parser, major command argparser
    #                    parser_list, save subcommand parser list
    #   @Return:
    #   @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('getsphw',
                                   help='''get SP hardware information''')
    sub_parser.add_argument('-F', dest='file',
                            required=False,
                            help='the loacl path of get '
                                 'the configuration file')

    parser_list['getsphw'] = sub_parser

    return 'getsphw'


def getsphardware(client, args):
    """
    Function Description:query the Smart Provisioning hardware
     configuration file.
    Parameter:client refishClient: class object
    args object:CLI command
    Modify: 2019.3.12 Added error code processing. Such as 400 error code.
    Return Value: result of the redfish interface
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/SPService/DeviceInfo" % slotid
    resp = client.get_resource(url)
    if resp is None or resp.get("status_code", None) is None:
        return None
    return print_device_info(args, resp)


def print_device_info(args, resp):
    """
    功能描述:打印接口信息
    参数：args (list): parameter list
         resp (dict):通过 "/redfish/v1/Managers/1/SPService/DeviceInfo"
    获取到Redfish结果
    返回值：resp (dict) 通过 "/redfish/v1/Managers/1/SPService/DeviceInfo"
    获取到Redfish结果 or None
    修改：None
    """
    if resp['status_code'] == 200:
        info = resp.get('resource', None)
        if print_no_data(info):
            return resp
        if args.file is not None:
            if creat_res_file(args.file, info) is True:
                print('Success: successfully completed request')
            else:
                return None
        else:
            print_info(info)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
    elif resp['status_code'] == 500:
        print("Failure: the request failed due to an internal service error")
    elif resp['status_code'] == 400:
        print_exception_message(resp)
    else:
        common_function.print_status_code(resp)
    return resp


def print_no_data(info):
    """
    功能描述:打印'no data available for the resource'到控制台
    参数：info (dict):通过 "/redfish/v1/Managers/1/SPService/DeviceInfo"
    获取到Redfish结果
    返回值：(bool) 是否打印 no data
    修改：None
    """
    if info is None:
        print('no data available for the resource')
        return True
    del info["@odata.context"]
    del info["@odata.id"]
    del info["@odata.type"]
    if info.get('Actions', None) is not None:
        del info['Actions']
    del info['Name']
    del info['Id']
    info_len = len(info)
    if info_len == 0:
        print('no data available for the resource')
        return True
    return False


def print_exception_message(resp):
    """
    功能描述:根据resp打印异常信息
    参数：resp (dict):通过 "/redfish/v1/Managers/1/SPService/DeviceInfo"
    获取到Redfish结果
    返回值：None
    修改：None
    """
    try:
        message_info = resp.get('message')
        message_info = message_info.get('error')
        message_info = message_info.get('@Message.ExtendedInfo')
        message_info = message_info[0]
        message_info = message_info.get('Message')
        print('Failure: %s' % message_info)
    except (KeyError, IndexError, TypeError,
            IndexError, AttributeError) as e:
        print('Failure: status code 400.')
        print(e)


def creat_res_file(file_path, dict_info):
    """
    #=====================================================================
    #   @Method:  Export JSON files.
    #   @Param:   info, SP message dictionary
    #             args, command function parameter
    #   @Return:
    #   @author:
    #=====================================================================
    """
    # Check the path.
    file_dir = path.dirname(file_path)
    if path.exists(file_dir) is not True:
        print("Failure: the path does not exist")
        return False

    if path.isdir(file_path) is True:
        print("Failure: please specify a file name")
        return False
    try:
        json_obj = dumps(dict_info)
        common_function.write_file(file_path=file_path, file_content=json_obj)
    except OSError:
        print(FAIL)
        return False

    return True


def print_pcie_info(info):
    """
    print pcie info
    :param info:
    :return:
    """
    for pecie_item in info['PCIeCards']:
        print("-" * 60)
        print(FORMAT % ('DeviceName', pecie_item['DeviceName']))
        print(FORMAT % ('DeviceLocator', pecie_item['DeviceLocator']))
        print(FORMAT % ('Position', pecie_item['Position']))
        print('')

        for controller in pecie_item['Controllers']:
            print('[Controllers]')
            print(FORMAT % ('Model', controller['Model']))
            print(FORMAT % ('FirmwareVersion', controller['FirmwareVersion']))
            print(FORMAT % ('Manufacturer', controller['Manufacturer']))
            print('')

            for function_info in controller['Functions']:
                print('-' * 40)
                print(FORMAT % ('VendorId', function_info['VendorId']))
                print(FORMAT % ('Description', function_info['Description']))
                if "MacAddress" in function_info:
                    print(FORMAT % ('MacAddress', function_info['MacAddress']))
                print(FORMAT % ('DeviceId', function_info['DeviceId']))
                print(FORMAT % ('SubsystemId', function_info['SubsystemId']))
                print(FORMAT % ('CardType', function_info['CardType']))
                print(FORMAT %
                      ('SubsystemVendorId',
                       function_info['SubsystemVendorId']))
                print('')

                print('[BDFNumber]')
                print(FORMAT % ('BDF', function_info['BDFNumber']['BDF']))
                print(FORMAT %
                      ('RootBDF', function_info['BDFNumber']['RootBDF']))
            print('-' * 40)


def print_info(info):
    """
    #=====================================================================
    #   @Method:  print result
    #   @Param:   info，resource
    #   @Return:
    #   @author:
    #=====================================================================
    """
    if info is None:
        print('no data available for the resource')
        return

    for key in info:
        if key == "PCIeCards":
            print('[PCIeCards]')
            info_len = len(info['PCIeCards'])
            if info_len != 0:
                print_pcie_info(info)
                print("-" * 60)
