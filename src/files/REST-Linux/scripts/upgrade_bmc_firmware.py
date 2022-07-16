# -*- coding:utf-8 -*-
"""
Function: upgrade_bmc_firmware.py moudle. This moudle mainly involves the
Upgrade firmware, for example iBMC and CPLD function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2021
"""
import os
import sys
from scripts import common_function


def upgradebmcfirmware_init(parser, parser_dict):
    """
    Function Description:Initialize BMC firmware upgrade subcommands
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('upgradefw',
                                   help='''upgrade firmware''')

    sub_parser.add_argument('-F', dest='file',
                            required=False,
                            type=common_function.format_uri,
                            help='the local path and file name of upload file,'
                                 'file extensions should be ".hpm"')

    sub_parser.add_argument('-i', dest='imageuri',
                            required=False,
                            type=common_function.format_uri,
                            help='path of the upgrade package on a remote '
                                 'server. it is in the '
                                 'protocol://username:password@ip/directory/'
                                 'filename format. supported protocols include '
                                 'https, scp, sftp, cifs, and nfs')

    parser_dict['upgradefw'] = sub_parser

    return 'upgradefw'


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if args.imageuri is None and args.file is None:
        parser.error('usage: urest upgradefw [-h] [-i IMAGEURI] [-F FILE]')
    elif args.imageuri is not None and args.file is not None:
        parser.error('Failure: parameter "-i" or "-F" conflict')
    elif args.file is not None:
        if not os.path.exists(args.file):
            parser.error('Failure: the file does not exist')
        if not os.path.isfile(args.file):
            parser.error('Failure: invalid file')
        if str(args.file).split('.')[-1] != 'hpm':
            parser.error(
                'Failure: update firmware file type should be \'.hpm\'')
    elif args.imageuri is not None:
        protocol = common_function.get_protocol_type(args.imageuri)
        if not protocol:
            parser.error('the upgrade package path does not contain '
                         'a valid protocol')


def upgradebmcfirmware(client, args):
    """
    Function Description:BMC firmware upgrade
    Parameter:client refishClient:class object
    args object:CLI command
    Modify: 2019.1.17 Default timeout parameter normalization.
    2019.4.26 Change the name of the variable that obtains the progress result.
    """
    resp = post_simple_update(client, args)

    if resp is None:
        return None

    if resp['status_code'] == 202:
        get_resp = client.print_task_prog(resp,
                                          maxtime=common_function.MAX_TIMEOUT,
                                          flag="upgradefw")
        if get_resp is None:
            return None
        if get_resp == 'Exception':
            taskid = resp['resource']['@odata.id']
            task_resp = client.get_resource(taskid)
            if task_resp is None:
                return None
            if task_resp['status_code'] != 200:
                return task_resp

            message_id = \
                task_resp['resource']['Messages']['MessageId'].split(".")[-1]

            if message_id in ['FirmwareUpgradeError', 'FileTransferErrorDesc']:
                message_info = task_resp['resource']['Messages']['Message']
                pos = message_info.find('Details: ')
                message_info = message_info[(pos + 9):-1]
                print('Failure: %s' % message_info)
            else:
                print('Failure: ' + message_id)
            sys.exit(144)
        if get_resp == 'Completed':
            print('Success: successfully completed request.')
    elif resp['status_code'] == 400:
        err_400_proc(resp)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')

    return resp


def post_simple_update(client, args):
    """
    功能描述：post url
    参数： client (redfish_client):redfish接口
           parser (ArgumentParser):subcommand argparser.
           Export error messages when parameters are incorrect
           args (list):parameter list
    返回值：None
    异常描述：None
    """
    url = "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate"
    payload = get_payload_dict(client, args)
    if payload is None:
        return None

    # 2021.3.3 Modify: Changing the default timeout interval.
    resp = client.create_resource(url, payload,
                                  timeout=common_function.TIMEOUT_UPDATE)

    return resp


def get_payload_dict(client, args):
    """
    功能描述：urest 带内命令删除带内session
    参数： client (redfish_client):redfish接口
           parser (ArgumentParser):subcommand argparser.
           Export error messages when parameters are incorrect
           args (list):parameter list
    返回值：None
    异常描述：None
    """
    payload = {}
    if args.file is not None:
        if str(args.file).split('/')[-1] == args.file:
            filename = str(args.file).split("\\")[-1]
        else:
            filename = str(args.file).split('/')[-1]
        ret = upload_file(client, args, filename)
        if ret is False:
            return None
        payload['ImageURI'] = ('/tmp/web/' + filename)
    elif args.imageuri is not None:
        payload['ImageURI'] = args.imageuri
        payload['TransferProtocol'] = common_function.get_protocol_type(
            args.imageuri)

    return payload


def upload_file(client, args, filesname):
    """
    #==========================================================================
    #   @Method:  upload file
    #   @Param:
    #   @Return:
    #   @author:
    #==========================================================================
    """
    url_upload = "/redfish/v1/UpdateService/FirmwareInventory"
    file_obj = None
    try:
        with open(args.file, 'rb') as file_obj:
            files = {'imgfile': (filesname, file_obj, "multipart/form-data",
                                 {'user_name': (client.username)})}
            # 2021.3.3 Modify: Changing the default timeout interval.
            resp = client.create_resource(url_upload,
                                          files=files,
                                          timeout=(common_function.
                                                   TIMEOUT_UPDATE))
    except IOError:
        print("Failure: Failed to open the uploaded file. "
              "Please try again.")
        sys.exit(common_function.UREST_STATUS_CODE_127)
    finally:
        if file_obj:
            file_obj.close()

    if resp is None:
        return False

    if resp['status_code'] != 202:
        raise common_function.CustomError(resp)

    return None


def err_400_proc(resp):
    """
    #=====================================================================
    #   @Method:  When the response code is 400, process error messages
    #   @Param:   resp, redfish response result
    #   @Return:
    #   @author:
    #=====================================================================
    """
    error_message_dict = {
        'ActionParameterValueFormatError':
            'Failure: the value for -i is of a different '
            'format than the parameter can accept',
        'FirmwareUpgrading':
            'Failure: a file transfer task is being performed '
            'or an upgrade operation is in progress',
        'FileDownloadTaskOccupied':
            'Failure: other file is transfering, '
            'current upgrade request failed',
        'TaskLimitExceeded':
            'Failure: the asynchronous operation failed because the '
            'number of simultaneous tasks has reached the limit'
    }
    extend_info_list = resp['message']['error']['@Message.ExtendedInfo']
    message_id = extend_info_list[0]['MessageId'].split(".")[-1]
    if message_id in error_message_dict:
        print(error_message_dict.get(message_id))
    else:
        print('Failure: status code 400')
