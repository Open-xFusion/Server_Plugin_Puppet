# -*- coding:utf-8 -*-
"""
Function: add_user.py moudle. This moudle mainly involves the
Creating a User function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
from scripts import common_function


def adduser_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Creating a User
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('adduser',
                                   help='''add user''')
    sub_parser.add_argument('-N', dest='newusername', required=True,
                            help='''new user name''')
    sub_parser.add_argument('-P', dest='newpassword', required=True,
                            help='''new user password''')
    sub_parser.add_argument('-R', dest='role', required=True,
                            choices=['Administrator', 'Operator',
                                     'Commonuser', 'NoAccess',
                                     'CustomRole1',
                                     'CustomRole2', 'CustomRole3',
                                     'CustomRole4'],
                            help='''new user role''')

    parser_dict['adduser'] = sub_parser

    return 'adduser'


def adduser(client, args):
    """
    Function Description:Creating a User
    Parameter:client refishClient: class object
    args object:CLI command
    """
    url = "/redfish/v1/AccountService/Accounts"
    arg_dic = {'NoAccess': 'Noaccess'}
    role = arg_dic.get(args.role, args.role)
    global new_password
    new_password = args.newpassword
    payload = {
        "UserName": args.newusername,
        "Password": new_password,
        "RoleId": role
    }
    resp = client.create_resource(url, payload)
    if resp is None:
        return None
    if resp['status_code'] == common_function.REDFISH_STATUS_CODE_201:
        print('Success: successfully completed request')
    elif resp['status_code'] == common_function.REDFISH_STATUS_CODE_404:
        print('Failure: resource was not found')
    elif resp['status_code'] == common_function.REDFISH_STATUS_CODE_400:
        error_message(resp['message']['error']['@Message.ExtendedInfo'])
    else:
        print("Failure: the request failed due to an internal service error")
    return resp


def error_message(message):
    """
    Function Description:print adduser error message
    Parameter:message list: redfish interface Value
    """
    messageid = message[0]['MessageId'].split('.')[-1]
    message_info = common_function.change_message(message[0]['Message'])
    error_message_dict = {
        'CreateLimitReachedForResource':
            'Failure: the number of users reached the limit',
        'InvalidUserName':
            "Failure: %s" % message_info,
        'ResourceAlreadyExists':
            'Failure: the user already exists',
        'PropertyValueExceedsMaxLength':
            'Failure: the user name cannot exceed 16 characters',
        'UserNameIsRestricted':
            'Failure: the user name cannot be root',
        'RoleIdIsRestricted':
            'Failure: the root user must be an administrator',
        'PasswordComplexityCheckFail':
            'Failure: the password does not '
            'meet password complexity requirements',
        'InvalidPassword':
            'Failure: the password cannot be empty',
        'PropertyValueNotInList': "Failure: %s" % message_info,
        'AccountNotModified': 'Failure: the account modification request failed'
    }
    if messageid in error_message_dict:
        print(error_message_dict.get(messageid))
    else:
        print("Failure: %s" % common_function.replace_password(message_info,
                                                               new_password))
