# -*- coding:utf-8 -*-
"""
Function: get_sp_info.py moudle. This moudle mainly involves the
 querying Smart Provisioning Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
FORMAT = '%-30s: %s'


def getspinfo_init(parser, parser_list):
    """
    #=====================================================================
    #   @Method:  SP query subcommand
    #   @Param:   parser, major command argparser
    #                    parser_list, save subcommand parser list
    #   @Return:
    #   @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('getspinfo',
                                   help='''get SP service information''')

    parser_list['getspinfo'] = sub_parser

    return 'getspinfo'


def getspinfo(client, _):
    """
    #=====================================================================
    #   @Method: SP query subcommand processing function
    #   @Param:  client, RedfishClient object
    #   @Return:
    #   @author:
    #   @date:  2017-11-14 09:04:14
    #=====================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/SPService" % slotid
    resp = client.get_resource(url)
    if resp is None or resp.get("status_code", None) is None:
        print('no data available for the resource')
        return None
    if resp['status_code'] == 200:
        print_result(resp)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
    elif resp['status_code'] == 500:
        print("Failure: the request failed due to an internal service error")

    return resp


def print_result(resp):
    """
    功能描述：打印 请求结果
    参数：resp (dict):redfish 接口返回值
    返回值：None
    异常描述：None
    修改：None
    """
    info = resp.get('resource', None)
    if info is None:
        print('no data available for the resource')
        return
    for key in info:
        if key in ["SPStartEnabled", "SysRestartDelaySeconds"]:
            print(FORMAT % (key, info[key]))
        if key == "Version":
            print('')
            print('[%s]' % key)
            ver = info['Version']
            if ver is None:
                continue
            for ver_key in ver:
                print(FORMAT % (ver_key, ver[ver_key]))
