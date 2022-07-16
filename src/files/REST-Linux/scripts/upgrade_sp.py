# -*- coding:utf-8 -*-
"""
Function: upgrade_sp.py moudle. This moudle mainly involves the
Querying the Enabling Status of the Character Device Channel for
Communication Between the uREST and iBMC function.
Copyright Information: xFusion Digital Technologies Co., Ltd. All Rights Reserved © 2020
"""
import time
import sys
from scripts import common_function

_REDFISH_FAILED = "Failure"
progress_url = None
image_type = None
progress_failure = "Failure: request progress failed."
# 开始请求进度
start_request_progress = True
# 进度显示的间隔时间 1s
PROGRESS_INTERVAL_TIME = 1


def upgradesp_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    upgrading Smart Provisioning.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('upgradesp',
                                   help='''upgrade SP''')
    sub_parser.add_argument('-i', dest='imageuri',
                            required=True,
                            help='path of the upgrade package on a remote '
                                 'server. it is in the '
                                 'protocol://username:password@ip/directory/'
                                 'filename format.')
    sub_parser.add_argument('-si', dest='signatureuri',
                            required=True,
                            help='path of the upgrade package digital signature'
                                 ' file on a remote server. it is in the '
                                 'protocol://username:password@ip/directory/'
                                 'filename format.')
    sub_parser.add_argument('-T', dest='imagetype',
                            required=True,
                            choices=['Firmware', 'SP'],
                            help='''type of the upgrade package''')

    sub_parser.add_argument('-PARM', dest='parameter',
                            required=True,
                            help='\'all\' indicates the entire upgrade '
                                 'package or a specific upgrade package')

    sub_parser.add_argument('-M', dest='mode',
                            required=True,
                            choices=['Auto', 'Full', 'Recover', 'APP',
                                     'Driver'],
                            help='''mode of the upgrade''')

    sub_parser.add_argument('-ACT', dest='activemethod',
                            required=True,
                            help='''how does the upgrade take effect''')

    parser_dict['upgradesp'] = sub_parser

    return 'upgradesp'


def upgradesp(client, args):
    """
    Function Description:upgrading Smart Provisioning
    Parameter:client refishClient: class object
    args object:CLI command
    Modify: 2019.1.17 Default timeout parameter normalization.
    Return Value: resp dict:return value of the redfish interface
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/SPService/SPFWUpdate/1/" \
          "Actions/SPFWUpdate.SimpleUpdate" % slotid

    payload = {'ImageURI': args.imageuri, 'SignalURI': args.signatureuri,
               'ImageType': args.imagetype,
               'Parameter': args.parameter, 'UpgradeMode': args.mode,
               'ActiveMethod': args.activemethod}

    resp = client.create_resource(url, payload,
                                  timeout=common_function.TIMEOUT_THIRTY)

    if resp is None:
        return None

    if resp['status_code'] == 200:
        global image_type
        image_type = args.imagetype
        resp = request_upgrade_progress(client)
    elif resp['status_code'] == 400:
        err_400_proc(resp)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
    else:
        common_function.print_status_code(resp)

    return resp


def get_upgrade_progress(client, resp):
    """
    Function:
        10s 之内请求一次进度
    Args:
        client  (RedfishClient):  对象
        resp （dict）:通过progress_url请求回来的资源
    Returns:
        None
    Raises:
        AttributeError ：属性错误
    Examples:
        find, process, resp = get_upgrade_progress(client, resp)
    Author:
    Date:  2020/06/22
    """
    try:
        fw_upgrade_json = resp.get('resource')
        tran_progress = fw_upgrade_json.get("TransferProgressPercent")
        progress = fw_upgrade_json.get("UpgradeProgress", tran_progress)
        count = 10
        while count > -1 and progress is None:
            time.sleep(1)
            count = count - 1
            status_code, resp = get_progress_url_resource(client)
            if status_code == 200:
                tran_progress = fw_upgrade_json.get("TransferProgressPercent")
                progress = fw_upgrade_json.get("UpgradeProgress",
                                               tran_progress)
            else:
                return False, None, resp

        if progress is None:
            error_info = get_error_message(resp)
            print('Failure: request progress timed out.%s' % error_info)
            sys.exit(144)
        return True, progress, resp
    except AttributeError as e:
        print('%s %s' % (progress_failure, str(e)))
        sys.exit(2)
    return False, None, resp


def get_error_message(resp):
    """
    Function:
        得到错误信息
    Args:
        resp  (str): 通过url 请求回来的资源信息
    Returns:
        error_info （str）:错误信息详情
    Raises:
        AttributeError ：属性错误
        TypeError : 类型转换错误
    Examples:
        error_info = get_error_message(resp)
    Author:
    Date:  2020/06/22
    """
    try:
        error_info = ''
        if "Messages" in resp.get('resource'):
            messages = resp['resource']['Messages'][0]
            if "Message" in messages:
                error_info = messages.get("Message", "")
    except (KeyError, AttributeError) as e:
        print('%s %s' % (progress_failure, str(e)))
        sys.exit(2)
    return error_info


def print_progress(client, resp):
    """
    Function:
        打印进度
    Args:
        client  (RedfishClient):  对象
        resp    (dict):通过progress_url请求回来的资源
    Returns:
        True/False (bool):是否继续打印进度
        resp  （dict）：对应的信息
    Raises:
        AttributeError ：属性错误
        TypeError : 类型转换错误
    Examples:
        progress_continue, resp = print_progress(client, resp)
    Author:
    Date:  2020/06/22
    """
    try:
        fw_upgrade_json = resp.get('resource')
        status = fw_upgrade_json.get("TransferState")
        if status == _REDFISH_FAILED:
            error_info = get_error_message(resp)
            print('Failure: request progress '
                  'failed.%s' % error_info)
            sys.exit(144)
        else:
            global start_request_progress
            if start_request_progress:
                find = True
                process = 0
                start_request_progress = False
            else:
                find, process, resp = get_upgrade_progress(client, resp)
            if find:
                if int(process) == 100:
                    print_success()
                    return False, resp

                sys.stdout.write("Progress: %d%%\r" % int(process))
                sys.stdout.flush()
                return True, None
    except (AttributeError, TypeError) as e:
        print('Failure: request progress failed.%s' % str(e))
        sys.exit(2)
    return False, resp


def get_progress_url_resource(client):
    """
    Function:
        通过progress_url获取对应的资源信息
    Args:
        client  (RedfishClient):  对象
    Returns:
        status_code (int): 状态码
        resp        （dict）:progress_url对应的资源信息
    Raises:
        AttributeError : 属性错误
    Examples:
        status_code, resp = get_progress_url_resource(client)
    Author:
    Date:  2020/06/22
    """
    try:
        resp = client.get_resource(progress_url)
        if resp is None:
            return None, None
        status_code = resp.get('status_code')
        if status_code != 200:
            common_function.print_status_code(resp)
            return status_code, resp
    except AttributeError as e:
        print('Failure: request progress failed.%s' % str(e))
        sys.exit(2)
    return status_code, resp


def request_upgrade_progress(client):
    """
    Function Description:requesting the upgrade progress
    Parameter:client refishClient: class object
    Return Value: resp dict:result of the redfish interface
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    global progress_url
    progress_url = "/redfish/v1/Managers/%s/SPService/SPFWUpdate/1" % slotid
    time.sleep(PROGRESS_INTERVAL_TIME)
    status_code, resp = get_progress_url_resource(client)
    if status_code != 200:
        return resp
    progress_continue, resp = print_progress(client, resp)
    if progress_continue is False:
        return resp
    return request_upgrade_progress(client)


def print_success():
    """
    Function:
        升级固件或者SP 成功时候打印的信息
    Args:
        None
    Returns:
        None
    Raises:
        None
    Examples:
        print_success()
    Author:
    Date:  2020/06/22
    """
    if image_type == 'Firmware':
        print('Success: file downloaded successfully, '
              'start SP for the file to take effect')
    else:
        print('Success: successfully completed request')


def err_400_proc(resp):
    """
    #=====================================================================
    #   @Method:  When the response code is 400, process error messages
    #   @Param:   resp, request response results
    #   @Return:
    #   @author:
    #=====================================================================
    """
    message_info = resp['message']['error']['@Message.ExtendedInfo'][0][
        'Message']

    print('Failure: %s' % message_info)
