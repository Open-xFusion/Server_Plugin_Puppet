# -*- coding:utf-8 -*-
"""
Function: add_sp_cfg.py moudle. This moudle mainly involves the
 creating an OS Deployment Resource of Smart Provisioning function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
import sys

from scripts import common_function


def addspcfg_init(parser, parser_list):
    """
    Function Description:add sp config init
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
            2020.1.11 delete SPNetDev.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('addspcfg',
                                   help='''create SP service config ''')
    sub_parser.add_argument('-T', dest='ServiceType',
                            type=str, required=True,
                            choices=['SPRAID', 'SPOSInstallPara'],
                            help='''create service type''')
    sub_parser.add_argument('-F', dest='file',
                            required=True,
                            help='create SP the local configuration file in '
                                 'JSON format. The file contains the '
                                 'attributes to be configured, '
                                 'for example, {"attribute":"value", '
                                 '"attribute2":"value2" ...}')
    parser_list['addspcfg'] = sub_parser

    return 'addspcfg'


def addspcfg(client, args):
    """
    #=====================================================================
    #   @Description:  add csr
    #   @Date:
    #=====================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    # Distinguish the configuration to be delivered.
    url = "/redfish/v1/Managers/" + slotid + "/SPService/" + args.ServiceType
    resp = client.get_resource(url)
    if resp is None:
        return None
    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
        else:
            print('Failure: status code ' + str(resp['status_code']))
        return resp
    # Read the file content.
    try:
        payload = common_function.payload_file(args.file,
                                               file_des='configuration')
    except common_function.CustomError as exception:
        print(exception)
        sys.exit(common_function.UREST_STATUS_CODE_2)

    if payload is None:
        return None
    if args.ServiceType == 'SPRAID':
        if payload.get('Id') is None:
            print("Failure: The file must contain the Id attribute")
            return None

    resp = client.create_resource(url, payload)
    if resp is None:
        return None

    if resp['status_code'] == 201:
        print('Success: successfully completed request')

    else:
        error_message(resp['message']['error']['@Message.ExtendedInfo'],
                      resp['status_code'])
    return resp


def error_message(message, error_code):
    """
    #=====================================================================
    #   @Method: Handle errors.
    #   @Param:  error_code
    #   @Return:
    #   @author:
    #=====================================================================
    """
    if error_code == 404:
        print("Failure: resource was not found")

    if error_code == 400:
        messageid = message[0]['MessageId'].split('.')[-1]
        if messageid == "OperationNotSupported":
            print("Failure: this operation is not supported")
        elif messageid == "FileCountReachedLimit":
            mesg = "the number of configuration files has reached the limit"
            print("Failure: %s" % mesg)
        else:
            print("Failure: %s" % change_message(message[0]['Message']))


def change_message(messageinfo):
    """
    #==========================================================================
    #   @Method:  changemessage Change strings with capitalized first letters
    and ended with '.' into strings with lowercase first letters and delete '.'.
    #   @Param:
    #   @Return:
    #   @author:
    #==========================================================================
    """
    if (messageinfo[0] >= 'A' and messageinfo[0] <= 'Z') \
            and (messageinfo[-1] == '.'):
        return messageinfo[0].lower() + messageinfo[1:-1]

    return messageinfo
