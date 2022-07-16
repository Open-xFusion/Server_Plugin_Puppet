# -*- coding:utf-8 -*-
"""
Function: get_user.py moudle. This moudle mainly involves the
Querying a User function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
from scripts import common_function

MEMBER_NULL = "failed to query information about the specified" \
              " user resource of a server."


def getuser_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    get user information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('getuser',
                                   help='''get user information''')
    sub_parser.add_argument('-N', dest='name',
                            required=False,
                            help='''user name''')

    parser_dict['getuser'] = sub_parser

    return 'getuser'


def getuser(client, args):
    """
    Function Description:get user information
    Parameter:client refishClient: class object
    args object:CLI command
    """
    # url path storage directory
    url = "/redfish/v1/AccountService/Accounts"

    resp = client.get_resource(url)
    if not resp:
        raise common_function.CustomError(common_function.USERS_INFO_NULL)

    if resp.get('status_code') != common_function.REDFISH_STATUS_CODE_200:
        raise common_function.CustomError(resp)

    resp = getuser_info(client, resp, args)
    return resp


def getuser_info(client, resp, args):
    """
    Function Description:Displays user information.
    Parameter:client refishClient: class object
    resp dict:redfish interface value
    args object:CLI command
    """
    flag = False
    for user_id in resp['resource']['Members']:
        url = user_id['@odata.id']
        user_resp = client.get_resource(url)
        if not user_resp:
            raise common_function.CustomError(common_function.USER_NOT_EXITS)

        if user_resp['status_code'] != common_function.REDFISH_STATUS_CODE_200:
            raise common_function.CustomError(user_resp)

        if args.name is None or args.name == user_resp['resource']['UserName']:
            flag = True
            print_resource(user_resp)

    if not flag:
        print('Failure: the user does not exist')
    else:
        print('-' * 60)

    return resp


def print_resource(user_resp):
    """
    Function Description:print resource
    Parameter:info dict:redfish interface value
    """
    info = user_resp['resource']
    format_str = "%-28s%-2s%-s"
    print('-' * 60)
    print(format_str % ('UserId', ":", info['Id']))
    print(format_str % ('UserName', ":", info['UserName']))
    print(format_str % ('RoleId', ":", info['RoleId']))
    print(format_str % ('Locked', ":", info['Locked']))
    print(format_str % ('Enabled', ":", info['Enabled']))
    vendor_dict = common_function.get_vendor_value(user_resp)
    print(format_str % ('LoginInterface', ":",
                        ','.join(vendor_dict['LoginInterface'])))
    if 'AccountInsecurePromptEnabled' in vendor_dict:
        print(format_str %
              ('AccountInsecurePromptEnabled', ":",
               vendor_dict['AccountInsecurePromptEnabled']))

    print_vendor_infomation(info)


def print_vendor_infomation(info):
    """
    Function Description:print vendor infomation
    Parameter:user_resp dict: redfish result
    """
    rule_key = "LoginRule"
    data_id_key = '@odata.id'
    format_str = "%-28s%-2s%-s"
    keys = ("FirstLoginPolicy",
            "SnmpV3AuthProtocol",
            "SnmpV3PrivProtocol",
            "SNMPEncryptPwdInit",
            "Deleteable")
    oem_dict = info.get(common_function.OEM_KEY)
    if not oem_dict:
        return

    vendor_dict = oem_dict.get(common_function.COMMON_KEY)
    if not vendor_dict:
        return

    for key in keys:
        if key in vendor_dict:
            print(format_str % (key, ":", vendor_dict.get(key)))

    # 1.rule_key:[] 2:rule_key not exit
    if rule_key not in vendor_dict:
        return

    login_value = vendor_dict.get(rule_key)
    rule_ids_init = list(filter(lambda x: x.get(data_id_key), login_value))
    rule_ids = [x.get(data_id_key) for x in rule_ids_init]
    login_rules = [f"Rule{str(x).split('/')[-1]}" for x in rule_ids]
    print(format_str % (rule_key, ":", login_rules))
