# -*- coding: utf-8 -*-
"""
Function: install_license.py moudle. This moudle mainly involves the
Installing the iBMC License function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2018-2020
"""
import os.path
import sys
import time
from scripts.common_function import REDFISH_STATUS_CODE_202
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import UREST_STATUS_CODE_144
from scripts.common_function import UREST_STATUS_CODE_127
from scripts.common_function import upload_file
from scripts.common_function import unpack_remote_server_path
from scripts.common_function import splice_remote_server_path
from scripts.common_function import REQUIRED_FLAG
from scripts.common_function import HELP_INFO


def installlicense_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Installing the iBMC License
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('installlicense',
                                   help='''install license''')

    sub_parser.add_argument('-C', dest='licensefile',
                            type=str,
                            required=True,
                            help='''the path of license.
                                   Local import:Folder/File name or File name.
                                   Remote import:File transfer
                                   protocol://User name:Password@IP
                                   address/Folder/File name.
                                   The file transfer protocols include
                                   the following: sftp, https, nfs,
                                   cifs, scp. ''')

    parser_dict['installlicense'] = sub_parser

    return 'installlicense'


def installlicense(client, args):
    """
    Function Description:Installing the iBMC License
    Parameter:client refishClient:class object
    args object:CLI command
    """
    # Obtain the slot number.
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/LicenseService" \
          "/Actions/LicenseService.InstallLicense" % slotid
    # Construct payload.
    if '://' not in args.licensefile:
        filename = str(args.licensefile).split('/')[-1]
        ret = upload_file(client, args.licensefile, filename)
        if ret is False:
            return
        payload = {"Type": "URI", "Content": '/tmp/web/' + filename}

    else:
        payload = {"Type": "URI", "Content": args.licensefile}

    resp = client.create_resource(url, payload)

    if resp is None:
        return None

    if resp.get('status_code') == REDFISH_STATUS_CODE_202:
        time.sleep(1)
        resp_task = client.print_task_prog(resp)
        if resp_task is None:
            return None

        if resp_task == 'Exception':
            _resptaskparse(resp, client)
            sys.exit(UREST_STATUS_CODE_144)
    else:
        _respparse(resp)

    return resp


def _resptaskparse(resp, client):
    """
    Function Description:Handle exception task state
    Parameter:client refishClient:class object
    resp dict:response information
    """

    taskid = resp['resource']['@odata.id']

    sys_resp = client.get_resource(taskid)
    if sys_resp is None:
        sys.exit(UREST_STATUS_CODE_127)

    if sys_resp['status_code'] != REDFISH_STATUS_CODE_200:
        message = (sys_resp['message']['error']['@Message.ExtendedInfo'][0][
            'Message']).lower()
        print('Failure: ' + message[:-1])
    else:
        # Return the task failure details
        message = (sys_resp['resource']['Messages']['Message']).lower()
        print('Failure: ' + message[:-1])


def _respparse(resp):
    """
    Function Description:Handle resp which is not 202
    Parameter:resp dict:response information
    """
    if resp['status_code'] == REDFISH_STATUS_CODE_200:
        print('Success: successfully completed request\r')
    else:
        messageid = resp['message']['error']['@Message.ExtendedInfo'][0].get(
            'MessageId')
        if 'Format' in messageid:
            print('Failure: import failed due to invalid path')
        else:
            message = (
                resp['message']['error']['@Message.ExtendedInfo'][0].get(
                    'Message')).lower()
            print('Failure: ' + message[:-1])
