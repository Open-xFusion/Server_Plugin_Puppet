# -*- coding:utf-8 -*-
"""
Function: set_user.py moudle. This moudle mainly involves the Modifying User
 Information function.
Copyright Information: xFusion Digital Technologies Co., Ltd. All Rights Reserved © 2021
"""
from scripts import common_function

USER_INFO_NULL = "the resource information of the user does not exist."
SET_ERROR = "failed to modify user information."
SUB_COMMAND = 'setuser'
DATA_ID_KEY = "@odata.id"
# Modify: 2021.08.28 Privacy-Involved Attributes
PASSWORD_KEY = "Password"
PR_PASSWD_KEY = "SnmpV3PrivPasswd"
PRIVACY_ATTRIBUTES = (PASSWORD_KEY,)
user_name = None


def set_user_init(parser, parser_dict):
    """
    Function Description:initializing the Command for Modifying User
     Information
    Parameter: parser_dict dict:dictionary format of subcommand and
     ArgumentParser
    """
    sub_parser = parser.add_parser(SUB_COMMAND,
                                   help='modify the following properties'
                                        ' of a user')
    sub_parser.add_argument('-N',
                            dest='name',
                            required=False,
                            help='user name. specify the user to be modified. '
                                 'if no user is specified, the command modifies'
                                 ' information about the current login user')
    sub_parser.add_argument('-NN',
                            dest='newname',
                            required=False,
                            help='new user name.')
    sub_parser.add_argument('-NP',
                            dest='newpassword',
                            required=False,
                            help='new user password.')

    sub_parser.add_argument('-R',
                            dest='role',
                            required=False,
                            choices=['Administrator', 'Operator', 'Commonuser',
                                     'NoAccess',
                                     'CustomRole1', 'CustomRole2',
                                     'CustomRole3', 'CustomRole4'],
                            help='new user role.')
    sub_parser.add_argument('-L',
                            dest='locked',
                            required=False,
                            choices=['False'],
                            help='new user lockout status.')
    sub_parser.add_argument('-E',
                            dest='enabled',
                            required=False,
                            choices=['True', 'False'],
                            help='whether the user is enabled.')
    sub_parser.add_argument('-AP',
                            dest='accountInsecurePromptEnabled',
                            required=False,
                            choices=['True', 'False'],
                            help='whether the user prompt for unsafe'
                                 ' information.')

    add_other_argument(sub_parser)
    parser_dict[SUB_COMMAND] = sub_parser
    return SUB_COMMAND


def add_other_argument(sub_parser):
    """
    Function Description:add other argument
    Parameter:sub_parser object:subcommand ArgumentParser object
    """
    sub_parser.add_argument('-FLP',
                            dest='firstLoginPolicy',
                            required=False,
                            choices=['ForcePasswordReset',
                                     'PromptPasswordReset'],
                            help='password change policy upon the first login'
                                 ' after the account password is changed.')
    sub_parser.add_argument('-LI',
                            dest='loginInterface',
                            required=False,
                            nargs='*',
                            choices=["Web", "SNMP", "IPMI", "SSH",
                                     "SFTP", "Local", "Redfish"],
                            help='user login interface')
    sub_parser.add_argument('-SAP',
                            dest='snmpV3AuthProtocol',
                            required=False,
                            choices=["MD5", "SHA", "SHA256", "SHA384",
                                     "SHA512"],
                            help='SNMPv3 authentication algorithm.')
    sub_parser.add_argument('-SPP',
                            dest='snmpV3PrivProtocol',
                            required=False,
                            choices=["DES", "AES", "AES256"],
                            help='SNMPv3 encryption algorithm.')
    sub_parser.add_argument('-SEP',
                            dest='encryptionPassword',
                            required=False,
                            help='encryption password for the SNMPv3 user'
                                 ' authentication.')
    sub_parser.add_argument('-LR', dest='loginRule',
                            required=False,
                            nargs='+',
                            choices=['Rule1', 'Rule2', 'Rule3'],
                            help='login rules')


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
              parser object:subcommand ArgumentParser object
    """
    user_param = (args.username, args.name)
    if all(user_name is None for user_name in user_param):
        parser.error('at least one parameter of -N and -U must be specified')

    global user_name
    user_name = args.username if args.name is None else args.name

    fun_param = (args.newname, args.role,
                 args.locked, args.enabled,
                 args.newpassword,
                 args.accountInsecurePromptEnabled,
                 args.firstLoginPolicy,
                 args.loginInterface, args.snmpV3AuthProtocol,
                 args.snmpV3PrivProtocol,
                 args.encryptionPassword,
                 args.loginRule)
    if all(param is None for param in fun_param):
        parser.error('at least one parameter of -UN,-R,-L,-E,-AP,-FLP,'
                     '-LI,-SAP,-SPP,-SEP and -LR must be specified')


def get_user_url(client, members):
    """
    Function Description:get user id
    Parameter:client redfishClient: class object
               members list:redfish value
               args object:CLI command
    Modify: 2021.08.23 Modify whether the resource belongs to user_resp
                        and user_resp['resource'].get("UserName") to
                        solve the problem that the'urest setuser -LI SSH'
                        command is executed successfully.
            2021.08.23 When the URL of a specified user cannot be found,
                        the system displays "Failure: the user does not exist."
                        to solve the problem that the user information is
                        modified successfully when a user enters a user name
                        that does not exist.
    """
    for member in members:
        url = member.get(DATA_ID_KEY)
        user_resp = client.get_resource(url)
        if not user_resp:
            raise common_function.CustomError(USER_INFO_NULL)

        if user_resp.get('status_code') != \
                common_function.REDFISH_STATUS_CODE_200:
            raise common_function.CustomError(user_resp)

        if 'resource' not in user_resp:
            raise common_function.CustomError(USER_INFO_NULL)

        if user_name == user_resp['resource'].get("UserName"):
            return url

    raise common_function.CustomError(common_function.USER_NOT_EXITS)


def set_user(client, args):
    """
    Function Description:set user infomation
    Parameter:client refishClient: class object
              parser object:subcommand ArgumentParser object
              args object:CLI command
    """
    url = "/redfish/v1/AccountService/Accounts"
    resp = client.get_resource(url)

    if not resp:
        raise common_function.CustomError(common_function.USERS_INFO_NULL)

    if resp.get('status_code') != common_function.REDFISH_STATUS_CODE_200:
        raise common_function.CustomError(resp)

    if 'resource' not in resp:
        raise common_function.CustomError(common_function.USERS_INFO_NULL)

    members = resp['resource'].get('Members')
    if not members:
        raise common_function.CustomError(common_function.USER_NOT_EXITS)

    user_url = get_user_url(client, members)
    resp = set_specify_user(client, args, user_url)
    return resp


def set_specify_user(client, args, user_url):
    """
    Function Description:set user infomation
    Parameter:client refishClient: class object
              args object:CLI command
              user_url str:user url
    Modify: 2021.08.28 retrieve error information in the 200 state.
    """
    delete_key = "%s/%s/" % (common_function.OEM_KEY,
                             common_function.COMMON_KEY)
    payload = get_payload(args)
    set_resp = client.set_resource(user_url, payload)
    if not set_resp:
        raise common_function.CustomError(SET_ERROR)

    if set_resp.get('status_code') != common_function.REDFISH_STATUS_CODE_200:
        common_function.print_error_message(set_resp,
                                            p_attributes=PRIVACY_ATTRIBUTES,
                                            key=delete_key)
        return set_resp

    common_function.print_result(set_resp,
                                 p_attributes=PRIVACY_ATTRIBUTES,
                                 key=delete_key)
    return set_resp


def get_payload(args):
    """
    Function Description:get request body
    Parameter: args object:CLI command
    """
    payload_init = {
        "UserName": args.newname,
        PASSWORD_KEY: args.newpassword,
        "RoleId": 'Noaccess' if args.role == 'NoAccess' else args.role,
        "Locked": args.locked,
        "Enabled": args.enabled,
        common_function.OEM_KEY: {
            common_function.COMMON_KEY: {
                "AccountInsecurePrompt"
                "Enabled": args.accountInsecurePromptEnabled,
                "FirstLoginPolicy": args.firstLoginPolicy,
                "LoginInterface": args.loginInterface,
                "SnmpV3AuthProtocol": args.snmpV3AuthProtocol,
                "SnmpV3PrivProtocol": args.snmpV3PrivProtocol,
                PR_PASSWD_KEY: args.encryptionPassword,
                "LoginRule": args.loginRule
            }
        }
    }
    payload = {}
    for key_init, value in payload_init.items():
        if value is None or key_init == common_function.OEM_KEY:
            continue
        elif value in ["True", "False"]:
            value = value == str(True)
        payload[key_init] = value

    common_key_dict = payload_init[common_function.OEM_KEY][
        common_function.COMMON_KEY]

    common_key_value = {}
    for key, value in common_key_dict.items():
        if value is None:
            continue
        elif value in ["True", "False"]:
            value = value == str(True)
        common_key_value[key] = value

    if common_key_value:
        payload[common_function.OEM_KEY] = {
            common_function.COMMON_KEY: common_key_value}

    return payload
