# -*- coding:utf-8 -*-
"""
Function: get_sp_result.py moudle. This moudle mainly involves the querying
 the Configuration Result Resources of the Smart Provisioning Service function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
from json import dumps
from os import path
from scripts import common_function

FORMAT = '%-30s: %s'
PRINT_FORMAT = "-" * 60
FAIL = "Failure: insufficient permission for the file or file name not " \
       "specified, perform this operation as system administrator/root, " \
       "or specify a file name"


def getspresult_init(parser, parser_list):
    """
    #=====================================================================
    #   @Method:  SP query subcommand
    #   @Param:   parser, major command argparser
    #                    parser_list, save subcommand parser list
    #   @Return:
    #   @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('getspresult',
                                   help='''get SP result information''')
    sub_parser.add_argument('-F', dest='file',
                            required=False,
                            help='the loacl path of '
                                 'get the configuration file')

    parser_list['getspresult'] = sub_parser

    return 'getspresult'


def getspresult(client, args):
    """
    #=====================================================================
    #   @Method: SP query subcommand processing function
    #   @Param:  client, RedfishClient object
    #   @Return:
    #   @author:
    #   @date:  2017-8-30 09:04:14
    #=====================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/SPService/SPResult/1" % slotid
    resp = client.get_resource(url)
    flag, resp = no_data(resp)
    if flag:
        return resp
    if resp['status_code'] == 200:
        info = resp.get('resource', None)
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

    return resp


def no_data(resp):
    """
    功能描述:通过url"/redfish/v1/Managers/1/SPService/SPResult/1"
    获取到的redfish接口内容
    参数：resp (dict): redfish 接口内容
    返回值：resp (dict): redfish 接口内容
    修改：None
    """
    message = 'no data available for the resource'
    if resp is None or resp.get("status_code", None) is None:
        print(message)
        return True, None
    if resp.get('status_code') == 200:
        info = resp.get('resource', None)
        if info is None:
            print(message)
            return True, resp
        del info["@odata.context"]
        del info["@odata.id"]
        del info["@odata.type"]
        if info.get('Actions', None) is not None:
            del info['Actions']
        del info['Name']
        del info['Id']
        len_info = len(info)
        if len_info == 0:
            print(message)
            return True, resp
    return False, resp


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


def print_detail(key, info):
    """
    Function Description:print detail
    Parameter:key str: Key value
    info dict:result info
    """
    len_info = len(info[key].get('Detail'))
    if len_info != 0:
        detail_info = info[key].get('Detail')
        for detail in detail_info:
            print("-" * 40)
            for detail_key in detail:
                print(FORMAT % (detail_key, detail[detail_key]))
        print("-" * 40)


def print_erase(info):
    """
    Function Description:print erase
    Parameter:info dict:sp drive erase result info
    """
    for erase_key in info:
        if erase_key not in ["Details", "DriveList"]:
            print(FORMAT % (erase_key, info[erase_key]))
        if erase_key == "Details":
            detail_info = info['Details']
            for detail in detail_info:
                print("-" * 50)
                print_erase(detail)
        if erase_key == "DriveList":
            drive_info = info['DriveList']
            for drive in drive_info:
                for drive_key in drive:
                    print(FORMAT % (drive_key, drive[drive_key]))
                print(" " * 40)
            print("-" * 40)


def print_info(info):
    """
    Function Description:print result
    Parameter:info dict: result of the redfish interface
    Modify: Print diagnostic progress.
            2019.11.25 The display format is modified.
    """
    if info is None:
        print('no data available for the resource')
        return

    for key in info:
        if key == "Status":
            print(PRINT_FORMAT)
            print('[Status]\n')
            print(FORMAT % ('Status', info['Status']))
        if key == "Upgrade":
            print(PRINT_FORMAT)
            print('[Upgrade]\n')
            print(FORMAT % ('Progress', info['Upgrade']['Progress']))
            print(FORMAT % ('Operation', info['Upgrade']['Operation']))
            print_detail(key, info)

        if key == "OSInstall":
            print(PRINT_FORMAT)
            print('[OSInstall]\n')
            for os_key in info['OSInstall']:
                print(FORMAT % (os_key, info['OSInstall'][os_key]))

        if key == "RaidCfg":
            print(PRINT_FORMAT)
            print('[RaidCfg]\n')
            print(FORMAT % ('Progress', info['RaidCfg']['Progress']))
            print_detail(key, info)

        if key == "Diagnose":
            print(PRINT_FORMAT)
            print('[Diagnose]\n')
            print(FORMAT % ('Operate', info['Diagnose']['Operate']))
            print(FORMAT % ('DiagFinished', info['Diagnose']['DiagFinished']))
            print_detail(key, info)

        if key == "DriveErase":
            print(PRINT_FORMAT)
            print('[DriveErase]\n')
            print_erase(info['DriveErase'])

    print(PRINT_FORMAT)
