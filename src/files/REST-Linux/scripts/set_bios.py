# -*- coding:utf-8 -*-
"""
Function: set_bios.py moudle. This moudle mainly involves the
 setting the BIOS function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2019-2021
"""
import sys

from scripts import common_function

ATTRIBUTES = 'Attributes'


def setbios_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Setting the BIOS.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('setbios',
                                   help='''set BIOS setup attributes''')
    sub_parser.add_argument('-A', dest='attribute',
                            required=False,
                            help='''attribute name''')
    sub_parser.add_argument('-V', dest='value',
                            required=False,
                            help='''attribute value''')
    sub_parser.add_argument('-F', dest='file',
                            required=False,
                            help='set the local BIOS configuration file in '
                                 'JSON format. The file contains the '
                                 'attributes to be configured, for example, '
                                 '{"attribute":"value", '
                                 '"attribute2":"value2" ...}')
    parser_dict['setbios'] = sub_parser

    return 'setbios'


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    message = 'parameter error. set -A and -V or set -F only'
    if args.file is None:
        if common_function.has_none(args.value, args.attribute):
            parser.error(message)
    else:
        if not common_function.all_none(args.value, args.attribute):
            parser.error(message)


def setbios(client, args):
    """
    #=====================================================================
    #   @Method: BIOS menu item setting subcommand processing function
    #   @Param:  client, RedfishClient object
                 args, parameter list
    #   @Return:
    #   @author:
    #=====================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    payload = parameter_processing(client, args, slotid)
    if payload is None:
        return None

    resp = set_bios_info(client, payload, slotid)
    if resp is None:
        return None

    if resp['status_code'] == 200:
        print('Success: successfully completed request')
    else:
        error_message(resp['message']['error']['@Message.ExtendedInfo'],
                      resp['status_code'])

    return resp


def parameter_processing(client, args, slotid):
    """
    #=====================================================================
    #   @Method: parameter processing
    #   @Param:  client, RedfishClient object
                 args, parameter list
                 slotid, slot number
    #   @Return:
    #   @author:
    #=====================================================================
    """
    payload = None
    if args.attribute and args.value and args.file is None:
        payload = payload_attribute(client, args, slotid)

    if args.file:
        try:
            file_json_object = (common_function
                                .payload_file(args.file,
                                              file_des='configuration'))
        except common_function.CustomError as exception:
            print(exception)
            sys.exit(common_function.UREST_STATUS_CODE_2)

        payload = {ATTRIBUTES: file_json_object}
    return payload


def payload_attribute(client, args, slotid):
    """
    #=====================================================================
    #   @Method: single BIOS item setting parameter processing
    #   @Param:  client, RedfishClient object
                 args, parameter list
                 slotid, slot number
    #   @Return:
    #   @author:
    #=====================================================================
    """
    resp = getbios_attribute(client, slotid)
    if resp is None:
        return None
    if args.attribute in resp:
        if isinstance(resp[args.attribute], int):
            try:
                value = int(args.value)
            except ValueError:
                print("Failure: incorrect -V value")
                sys.exit(common_function.UREST_STATUS_CODE_2)

            payload = {ATTRIBUTES: {args.attribute: value}}
            return payload

        payload = {ATTRIBUTES: {args.attribute: args.value}}
        return payload

    print('Failure: the attribute does not exist')
    sys.exit(common_function.UREST_STATUS_CODE_2)


def getbios_attribute(client, slotid):
    """
    #=====================================================================
    #   @Method: Obtain BIOS items.
    #   @Param:  client, RedfishClient object
                 slotid, slot number
    #   @Return:
    #   @author:
    #=====================================================================
    """
    url = "/redfish/v1/Systems/%s/Bios" % slotid
    resp = client.get_resource(url)
    if resp is None:
        return None

    if resp['status_code'] == 200:
        info = resp['resource'][ATTRIBUTES]
        return info
    if resp['status_code'] == 404:
        print('Failure: resource was not found')
    else:
        print("Failure: the request failed due to an internal service error")

    return resp


def set_bios_info(client, payload, slotid):
    """
    Function Description:Setting BIOS information.
    Parameter:client refishClient: class object
    payload dict: request message
    slotid str:the slot ID of the server
    Modify: 2019.1.17 Default timeout parameter
    Return Value: resp dict:result of the redfish interface
    """
    url = "/redfish/v1/Systems/%s/Bios/Settings" % slotid
    resp = client.get_resource(url)
    if resp is None:
        return None

    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
        else:
            print("Failure: the request failed due "
                  "to an internal service error")
        return resp

    resp = client.set_resource(url, payload,
                               timeout=common_function.TIMEOUT_THIRTY)

    return resp


def error_message(message, error_code):
    """
    #=====================================================================
    #   @Method:  error handling
    #   @Param:  error_code
    #   @Return:
    #   @author:
    #=====================================================================
    """
    key_list = ['SettingPropertyFailed', 'PropertyValueTypeError',
                'PropertyValueNotInList',
                'PropertyImmutable', 'PropertyNotWritable',
                'SettingPropertyFailedExtend',
                'PropertyValueFormatError', 'ValueOutOfRange',
                'PropertyScalarIncrement',
                'SettingBootOrderFailed', 'PropertyModificationNotSupported']
    if error_code == 404:
        print("Failure: resource was not found")
    elif error_code == 400:
        messageid = message[0]['MessageId'].split('.')[-1]

        if messageid == 'PropertyModificationNeedPrivilege':
            print('Failure: you do not have the required '
                  'permissions to perform this operation')
        elif messageid == 'MalformedJSON':
            print("Failure: JSON file format fail")
        elif messageid == 'PropertyUnknown':
            print(
                "Failure: %s" % change_message(message[0]['Message']).replace(
                    'properties',
                    ATTRIBUTES))
        elif messageid in key_list:
            print("Failure: " + change_message(message[0]['Message']))
        else:
            print('Failure: the request '
                  'failed due to an internal service error')
    else:
        print("Failure: the request failed due to an internal service error")


def change_message(messageinfo):
    """
    #==========================================================================
    #   @Method:  changemessage
    #             Delete 'Attributes/'.  Replace 'property' with 'attribute'.
    #             Change strings with capitalized first letters
                  and ended with '.' into strings with lowercase first
    #             letters and delete '.'.
    #   @Param:
    #   @Return:
    #   @author:
    #==========================================================================
    """
    messageinfo = (messageinfo.replace('Attributes/',
                                       '')).replace('property', 'attribute')

    if (messageinfo[0] >= 'A' and messageinfo[0] <= 'Z') \
            and (messageinfo[-1] == '.'):
        return messageinfo[0].lower() + messageinfo[1:-1]

    return messageinfo
