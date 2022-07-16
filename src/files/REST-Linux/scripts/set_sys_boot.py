# -*- coding: utf-8 -*-
"""
Function: set_sys_boot.py moudle. This moudle mainly involves the
setting system boot information. function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
import sys
from scripts import common_function


def setsysboot_init(parser, parser_list):
    """
    #=========================================================================
    #   @Description:  set system boot information init
    #   @Method:  setsysboot_init
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """

    sub_parser = parser.add_parser('setsysboot',
                                   help='''set system boot information''')
    sub_parser.add_argument('-T', dest='target',
                            type=str, required=False,
                            help='''boot source override target''',
                            choices=['None', 'Pxe', 'Floppy', 'Cd', 'Hdd',
                                     'BiosSetup'])
    sub_parser.add_argument('-TS', dest='tenabled',
                            type=str, required=False,
                            help='''boot source override Enabled''',
                            choices=['Once', 'Disabled', 'Continuous'])
    sub_parser.add_argument('-M', dest='mode',
                            type=str, required=False,
                            help='''boot source override mode''',
                            choices=['Legacy', 'UEFI'])
    sub_parser.add_argument('-MS', dest='menabled',
                            type=str, required=False,
                            help='boot source override mode change enabled',
                            choices=['True', 'False'])
    sub_parser.add_argument('-Q', dest='sequence', nargs='*',
                            type=str, required=False,
                            help='system boot order,four parameters that are '
                                 'not duplicate must be specified, '
                                 'example: -Q Cd Pxe Hdd Others ')

    parser_list['setsysboot'] = sub_parser

    return 'setsysboot'


def print_error_message(k, msgs, boot_enable_key):
    """
    #=========================================================================
    #   @Description:  _printf error messages
    #   @Method:  _printferrormessages
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """
    if msgs is None:
        return

    if k == 1:
        error = 'Failure: some of the settings failed. '
        error = error + 'possible causes include the following:'
        print(error)
        for msgs_info in msgs:
            mgsagr = msgs_info['RelatedProperties'][0]
            msg = ""

            if mgsagr == '#/Boot/BootSourceOverrideMode':
                msg = mgsagr.replace('#/Boot/', '')
            if boot_enable_key in mgsagr:
                msg = boot_enable_key
            print('         the property %s cannot be changed.' % msg)
    if k == 0:
        i = 0
        for msgs_info in msgs:
            mgsagr = msgs_info['RelatedProperties'][0]
            msg = ""
            if mgsagr == '#/Boot/BootSourceOverrideMode':
                msg = mgsagr.replace('#/Boot/', '')
            if boot_enable_key in mgsagr:
                msg = boot_enable_key

            if i == 0:
                print('Failure: the property %s cannot be change' % msg)
            else:
                print('         the property %s cannot be change' % msg)
            i = i + 1


def _sequencev3tov5(inputs):
    """
    #=======================================================================
    #   @Description:  _sequencev3tov5
    #   @Method:  _sequencev3tov5
    #   @Param:
    #   @Return:
    #   @Date:
    #=======================================================================
    """
    if inputs == 'Hdd':
        return 'HardDiskDrive'
    if inputs == 'Cd':
        return 'DVDROMDrive'
    if inputs == 'Pxe':
        return 'PXE'
    if inputs == 'Others':
        return 'Others'
    return 'Others'


def _checkbootsequence(sequence):
    """
    #=======================================================================
    #   @Description:  set boot sequence
    #   @Method:  _setbootsequence
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """

    if len(sequence) != 4:
        return False

    cddvd = False
    hdd = False
    pxe = False
    other = False

    for i in range(0, 4):
        if sequence[i] == 'Cd':
            cddvd = True
        if sequence[i] == 'Hdd':
            hdd = True
        if sequence[i] == 'Pxe':
            pxe = True
        if sequence[i] == 'Others':
            other = True

    if cddvd is not True \
            or hdd is not True \
            or pxe is not True \
            or other is not True:
        return False

    return True


def _setbootsequence(payload, client, slotid, sequence):
    """
    Function Description:set boot sequence
    Parameter:payload dict:redfish request body
    client refishClient: class object
    slotid list:server slotid
    sequence str:system boot sequence
    Modify: 2019.1.17 Default timeout parameter normalization.
    Return Value: resp dict:result of the redfish interface
    """
    url = "/redfish/v1/Systems/%s/Bios/Settings" % slotid
    resp = client.get_resource(url)

    if resp.get('status_code') == 200:

        attributes = resp['resource']['Attributes']
        if attributes is None:
            attributes = {}

        payloads = {"Attributes": attributes}
        for i in range(0, 4):
            value = _sequencev3tov5(sequence[i])
            payloads['Attributes']["BootTypeOrder%s" % i] = value
        timeout = common_function.TIMEOUT_ONE_HUNDRED_TWENTY
        resp_set = client.set_resource(url, payloads,
                                       timeout=timeout)

        if resp_set is None:
            return None
        if resp_set.get('status_code') == 200:
            return 'Success'

        common_function.print_status_code(resp_set)
        return resp_set

    value = [sequence[0], sequence[1], sequence[2], sequence[3]]
    payload['BootupSequence'] = value
    return resp


def make_payload(boot, payload_inner_dic):
    """
    #=========================================================================
    #   @Description:  set system boot
    #   @Method:  setsysboot
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """

    if boot != {} and payload_inner_dic != {}:
        payload = {"Boot": boot,
                   "Oem": {common_function.COMMON_KEY: payload_inner_dic}}
        return payload
    if boot != {} and payload_inner_dic == {}:
        payload = {"Boot": boot}
        return payload
    if boot == {} and payload_inner_dic != {}:
        payload = {"Oem": {common_function.COMMON_KEY: payload_inner_dic}}
        return payload

    return None


def _stringtobool(strs):
    """
    #=========================================================================
    #   @Description:  string to boolean
    #   @Method:  _stringtobool
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """
    if strs == 'False':
        return False
    return True


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if args.target is None and args.tenabled is None and \
            args.mode is None and args.menabled is None and \
            args.sequence is None:
        parser.error('at least one parameter must be specified')

    if args.sequence is not None and _checkbootsequence(
            args.sequence) is False:
        parser.error('Failure: four parameters that are not duplicate '
                     'must be specified for the system boot order.')


def setsysboot(client, args):
    """
    #=========================================================================
    #   @Description:  set system boot information
    #   @Method:  setsysboot
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """

    slotid = client.get_slotid()

    if slotid is None:
        return None
    boot = get_boot(args)

    url = "/redfish/v1/systems/%s" % slotid
    resp = client.get_resource(url)
    boot_enable_key = get_boot_enable_key(resp)
    payload_inner_dic = {}
    if args.menabled is not None:
        payload_inner_dic[boot_enable_key] = _stringtobool(args.menabled)

    ret = None
    if args.sequence is not None:
        ret = _setbootsequence(payload_inner_dic, client, slotid, args.sequence)
        if ret != 'Success':
            return ret

    payload = make_payload(boot, payload_inner_dic)

    if payload is None and ret == 'Success':
        print('Success: successfully completed request')
        return resp
    # Modify: 2019.4.18 The query method is added to update
    # the ETag in request header.
    resp = client.get_resource(url)
    if resp.get('status_code') != 200:
        return resp

    return set_boot(client, url, boot_enable_key, payload)


def set_boot(client, url, boot_enable_key, payload):
    """
    功能描述:通过 "/redfish/v1/systems/%s" % slotid 设置 payload内的相关内容
    参数：client (redfish_client):redfish接口
          url (str): 链接
          boot_enable_key(str):BootModeChangeEnabled
          or BootModeConfigOverIpmiEnabled
          payload (dict):设置项
    返回值：boot_enable_key (str)
    修改：None
    """
    resp = client.set_resource(url, payload)

    if resp is None:
        return None

    if resp['status_code'] == 200:
        # Some of the settings failed
        if resp['resource'].get('@Message.ExtendedInfo') is not None:
            messages = resp['resource']['@Message.ExtendedInfo']
            print_error_message(1, messages, boot_enable_key)
            sys.exit(144)
        else:
            print('Success: successfully completed request')
    else:
        # Failure
        if resp['status_code'] == 400:
            messages = resp['message']['error']['@Message.ExtendedInfo']
            print_error_message(0, messages, boot_enable_key)
        else:
            common_function.print_status_code(resp)

    return resp


def get_boot_enable_key(resp):
    """
    功能描述: 初始化boot_enable_key
    参数：resp (dict)，通过"/redfish/v1/systems/%s" % slotid请求到的值
    返回值：boot_enable_key (str)
    修改：None
    """
    boot_enable_key = change_key = "BootModeChangeEnabled"
    config_key = "BootModeConfigOverIpmiEnabled"
    if resp['status_code'] == 200:
        vendor_value = common_function.get_vendor_value(resp)
        if change_key in vendor_value:
            boot_enable_key = change_key
        if config_key in vendor_value:
            boot_enable_key = config_key
    return boot_enable_key


def get_boot(args):
    """
    功能描述: 初始化boot
    参数：args (list), 控制台CLI命令
    返回值：boot (dict), 封装target、tenabled、mode的字典
    修改：None
    """
    boot = {}
    if args.target is not None:
        boot['BootSourceOverrideTarget'] = args.target
    if args.tenabled is not None:
        boot['BootSourceOverrideEnabled'] = args.tenabled
    if args.mode is not None:
        boot['BootSourceOverrideMode'] = args.mode
    return boot
