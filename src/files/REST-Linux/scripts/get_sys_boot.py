# -*- coding: utf-8 -*-
"""
Function: get_sys_boot.py moudle. This moudle mainly involves the
 querying System Boot Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""

from scripts import common_function


def getsysboot_init(parser, parser_list):
    """
    #=========================================================================
    #   @Description: get system boot information subcommand init
    #   @Method:  getsysboot_init
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """

    sub_parser = parser.add_parser('getsysboot',
                                   help='''get system boot information''')
    parser_list['getsysboot'] = sub_parser

    return 'getsysboot'


def boot_sequence(inputs):
    """
    #=========================================================================
    #   @Description:  get sequence
    #   @Method:  getsequence
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """
    boot_sequence = inputs
    if inputs == 'HardDiskDrive':
        boot_sequence = 'Hdd'
    if inputs == 'DVDROMDrive':
        boot_sequence = 'Cd'
    if inputs == 'PXE':
        boot_sequence = 'Pxe'
    if inputs == 'Others':
        boot_sequence = 'Others'
    return boot_sequence


def get_sequence(resp_inner_dic, client, slotid):
    """
    Function Description:get sequence
    Parameter:oemxfusion dict:redfish request result
    client refishClient: class object
    slotid list:server slotid
    Modify: 2019.7.8 Modify the error of quering the
     system parameters about startup item.
    Return Value: ouput str:system boot sequence
    """
    url = "/redfish/v1/Systems/%s/Bios" % slotid
    resp = client.get_resource(url)
    if resp is None:
        return None
    if resp['status_code'] == 200:
        attributes = resp['resource']['Attributes']
        order_list = []
        for i in range(0, 4):
            if "BootTypeOrder%s" % i not in attributes:
                temp = "None"
                flag = True
            else:
                flag = False
                temp = boot_sequence(attributes["BootTypeOrder%s" % i])
            order_list.append(temp)

        if flag:
            ouput = "None"
        else:
            ouput = ",".join(order_list)

    else:
        sequence = resp_inner_dic['BootupSequence']
        ouput = ''
        for sequence_info in sequence:
            if sequence_info == sequence[-1]:
                ouput = ouput + sequence_info
            else:
                ouput = ouput + sequence_info + ','

    return ouput


def getsysboot(client, _):
    """
    #=========================================================================
    #   @Description:  get system boot information
    #   @Method:  getstateless_init
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    url = "/redfish/v1/systems/%s" % slotid
    resp = client.get_resource(url)
    if resp is None:
        return None
    if resp['status_code'] == 200:
        print_result(client, resp, slotid)
    return resp


def print_result(client, resp, slotid):
    """
    功能描述：打印 请求结果
    参数：resp (dict):redfish 接口返回值
    client (RedfishClient)
    slotid (str) :slotid
    返回值：None
    异常描述：None
    修改：None
    """
    change_key = "BootModeChangeEnabled"
    config_key = "BootModeConfigOverIpmiEnabled"
    length = 26
    mformat = '%-*s:%s'
    target = resp['resource']['Boot']['BootSourceOverrideTarget']
    tenabled = resp['resource']['Boot']['BootSourceOverrideEnabled']
    mode = resp['resource']['Boot']['BootSourceOverrideMode']
    mnabled = ""
    vendor_dict = common_function.get_vendor_value(resp)
    if change_key in vendor_dict:
        mnabled = vendor_dict[change_key]
    if config_key in vendor_dict:
        mnabled = vendor_dict[config_key]

    seq = get_sequence(vendor_dict, client, slotid)
    print(mformat % (length, 'BootSourceOverrideTarget', target))
    print(mformat % (length, 'BootSourceOverrideEnabled', tenabled))
    print(mformat % (length, 'BootSourceOverrideMode', mode))

    if change_key in vendor_dict:
        print(mformat % (length, change_key, mnabled))
    if config_key in vendor_dict:
        print(mformat % (length, config_key, mnabled))

    print(mformat % (length, 'BootupSequence', seq))
