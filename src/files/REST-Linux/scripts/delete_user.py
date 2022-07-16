# -*- coding:utf-8 -*-
"""
Function: delete_user.py moudle. This moudle mainly involves the
Deleting a User function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
from scripts import common_function


def deleteuser_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Deleting a User
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('deluser',
                                   help='''delete user''')
    sub_parser.add_argument('-N', dest='name', required=True,
                            help='''user to be deleted''')

    parser_dict['deluser'] = sub_parser

    return 'deluser'


def deleteuser(client, args):
    """
    Function Description:Deleting a User
    Parameter:client refishClient: class object
    args object:CLI command
    """
    url = "/redfish/v1/AccountService/Accounts"

    resp = client.get_resource(url)
    if resp is None:
        return None

    if resp['status_code'] != common_function.REDFISH_STATUS_CODE_200:
        error_message(resp)
        return resp

    for user_id in resp['resource']['Members']:
        url = user_id['@odata.id']
        user_resp = client.get_resource(url)
        if user_resp is None:
            return None
        if user_resp['status_code'] != common_function.REDFISH_STATUS_CODE_200:
            error_message(user_resp)
            return user_resp

        if args.name == user_resp['resource']['UserName']:
            account_resp = delete_account(client, url)
            return account_resp

    print('Failure: the user does not exist')
    return resp


def delete_account(client, url):
    """
    Function Description:delete user account
    Parameter:client refishClient: class object
    url str: redfish interface link
    """
    resp = client.delete_resource(url)
    if resp is None:
        return None

    if resp['status_code'] == common_function.REDFISH_STATUS_CODE_200:
        print('Success: successfully completed request')
    elif resp['status_code'] == common_function.REDFISH_STATUS_CODE_404:
        print('Failure: resource was not found')
    elif resp['status_code'] == common_function.REDFISH_STATUS_CODE_400:
        error_message(resp['message']['error']['@Message.ExtendedInfo'])
    else:
        print("Failure: the request failed due to "
              "an internal service error")
    return resp


def error_message(message):
    """
    Function Description:print deleteuser error message
    Parameter:message list: redfish interface Value
    """
    if message is None:
        print('Failure: status code 400.')
    messageid = message[0]['MessageId'].split('.')[-1]

    if messageid == 'UserIsLoggingIn':
        print('Failure: the user has already logged in to the CLI')
    elif messageid == 'AccountForbidRemoved':
        print('Failure: emergency users and trap v3 users cannot be deleted')
    elif messageid == 'AccountNotModified':
        print('Failure: the account modification request failed')
    else:
        print('Failure: %s' % common_function.change_message(
            message[0]['Message']))
