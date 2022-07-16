# -*- coding:utf-8 -*-
"""
Function: set_net_service.py moudle. This moudle mainly involves the
Setting Network Service Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2020
"""
import sys
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts.common_function import REDFISH_STATUS_CODE_400
from scripts.common_function import REDFISH_STATUS_CODE_404
from scripts.common_function import REDFISH_STATUS_CODE_501
from scripts.common_function import UREST_STATUS_CODE_144
from scripts import common_function

HELP_INFO = '''set network service'''
NMIS_INFO = 'indicates the protocol SSDP property NotifyMultica ' \
            'stIntervalSeconds range is 0 to 1800'
RESP = ''
FAILURE_INFO = 'Failure: some of the settings failed. possible causes ' \
               'include the following:'


def setnetservice_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    Setting Network Service Information
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('setnetsvc', help=HELP_INFO)
    sub_parser.add_argument('-PRO', dest='Protocol',
                            choices=['HTTP', 'HTTPS', 'SNMP', 'VirtualMedia',
                                     'IPMI', 'SSH',
                                     'KVMIP', 'SSDP', 'VNC'],
                            required=True,
                            help='set specify service '
                                 'information(State and Port value)')
    sub_parser.add_argument('-S', dest='State', choices=['True', 'False'],
                            required=False,
                            help='indicates if the protocol property State is '
                                 'enabled or disabled')
    sub_parser.add_argument('-p', dest='Port', type=int, required=False,
                            help='indicates the protocol property port range '
                                 'is 1 to 65535')
    sub_parser.add_argument('-NTTL', dest='NotifyTTL', type=int,
                            required=False,
                            help='indicates the protocol SSDP property '
                                 'NotifyTTL range is 1 to 255')
    sub_parser.add_argument('-NIPS', dest='NotifyIPv6Scope',
                            choices=['Link', 'Site', 'Organization'],
                            required=False,
                            help='indicates the protocol SSDP property '
                                 'NotifyIPv6Scope')
    sub_parser.add_argument('-NMIS', dest='NotifyMulticastIntervalSeconds',
                            required=False, type=int, help=NMIS_INFO)

    parser_dict['setnetsvc'] = sub_parser

    return 'setnetsvc'


def check_args_rang(parser, args):
    """
    Function Description:Check the input parameter range.
    Parameter:parser object:subcommand ArgumentParser object
    args object:CLI command
    """
    if args.Port is not None:
        if args.Port > 65535 or args.Port < 1:
            parser.error('''argument -p: invalid choice: '%s' (''' %
                         args.Port + '''choose from '1' to '65535')''')
            return None
    elif args.NotifyTTL is not None:
        if args.NotifyTTL > 255 or args.NotifyTTL < 1:
            parser.error('''argument -NTTL: invalid choice: '%s' (''' %
                         args.NotifyTTL + '''choose from '1' to '255')''')
            return None
    elif args.NotifyMulticastIntervalSeconds is not None:
        if args.NotifyMulticastIntervalSeconds > 1800 \
                or args.NotifyMulticastIntervalSeconds < 0:
            parser.error('''argument -NIPS: invalid choice: '%s' (''' %
                         args.NotifyMulticastIntervalSeconds +
                         '''choose from '0' to '1800')''')

    return None


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    # You must import the configured protocol type.
    if args.Protocol is None:
        parser.error('the -PRO parameter is required')
        return None
    # Check whether the parameters are in the specified ranges.
    check_args_rang(parser, args)
    # If the protocol type is non-SSDP.
    # check whether mandatory parameters are lacked or whether unnecessary
    # parameters are contained.
    if args.Protocol != 'SSDP':
        if (args.State or args.Port) is None:
            parser.error('at least another one parameter must' +
                         ' be specified besides -PRO')
            return None
        if args.NotifyTTL is not None:
            parser.error('argument -NTTL: %s is not required for this protocol'
                         % args.NotifyTTL)
        if args.NotifyIPv6Scope is not None:
            parser.error('argument -NIPS: %s is not required for this protocol'
                         % args.NotifyIPv6Scope)
        if args.NotifyMulticastIntervalSeconds is not None:
            parser.error('argument -NMIS: %s is not required for this protocol'
                         % args.NotifyMulticastIntervalSeconds)
    # If the protocol type is SSDP, check whether mandatory
    # parameters are lacked.
    else:
        arg = (args.State or args.Port or args.NotifyTTL
               or args.NotifyIPv6Scope or args.NotifyMulticastIntervalSeconds)
        if arg is None:
            parser.error('at least another one parameter '
                         'must be specified besides -PRO')
            return None

    return True


def add_oem_payload(prol, args, payload):
    """
    Function Description:Combine the OEM request body.
    Parameter:prol str:redfish key
    args object:CLI command
    payload dict:redfish Parameter
    Return Value: False: The input parameter is incorrect.
    True: The input parameter is correct.
    """
    if prol != 'Oem':
        return False
    # If the VNC protocol is used, add OEM attributes.
    vnc_dic = {}
    # Modify: 2019.12.26 Modify VNC request parameter exception.
    if args.State is not None:
        state = args.State == str(True)
        vnc_dic['ProtocolEnabled'] = state
        payload['Oem'][common_function.COMMON_KEY]['VNC'] = vnc_dic
    # Modify: 2017.08.26 Failed to set the VNC service enabling
    # status and port number using the urest tool.
    if args.Port is not None:
        vnc_dic['Port'] = args.Port
        payload['Oem'][common_function.COMMON_KEY]['VNC'] = vnc_dic
    else:
        return None

    return True


def add_payload(args, payload):
    """
    Function Description:add payload
    Parameter:args object:CLI command
    payload dict:redfish Parameter
    """
    for prol in payload:
        ret = add_oem_payload(prol, args, payload)
        # Add other protocol attributes.
        if ret is False:
            if args.State is not None:
                state = args.State == str(True)
                payload[prol]['ProtocolEnabled'] = state
            if args.Port is not None:
                payload[prol]['Port'] = args.Port
        else:
            pass
        # If the SSDP protocol is used, add the other three attributes.
        if args.Protocol == 'SSDP':
            if args.NotifyTTL is not None:
                payload[prol]['NotifyTTL'] = args.NotifyTTL
            if args.NotifyIPv6Scope is not None:
                payload[prol]['NotifyIPv6Scope'] = args.NotifyIPv6Scope
            if args.NotifyMulticastIntervalSeconds is not None:
                payload[prol]['NotifyMulticastIntervalSeconds'] = \
                    args.NotifyMulticastIntervalSeconds


def prt_err(flg, msg):
    """
    Function Description:Display error information.
    Parameter:flg int:message status flag
    msg str:message
    """
    if flg > 1:
        print("         %s" % msg)
    else:
        print("%s: %s" % ('Failure', msg))


def print_err_message(info):
    """
    Function Description:Display error information.
    Parameter:info dict:redfish value
    """
    result_flag = False
    if info is None:
        return None
        # If the number of array members in the error
        # message array is greater than 0.
        # multiple error messages exist.
    flag = len(info)
    if flag < 1:
        print('Success: successfully completed request')
        result_flag = True
    elif flag > 1:
        print(FAILURE_INFO)
    else:
        pass

    for idx in range(0, flag):
        # Insufficient permission
        if (info[idx]['MessageId'] ==
                'iBMC.1.0.PropertyModificationNeedPrivilege'
                or info[idx]['MessageId'] ==
                'Base.1.0.InsufficientPrivilege'):
            info[idx]['Message'] = 'you do not have the required ' \
                                   'permissions to perform this operation'
        # The attribute cannot be set.
        if (info[idx]['MessageId'] ==
                'iBMC.1.0.PropertyModificationNotSupported'):
            info[idx]['Message'] = 'the server did not support the ' \
                                   'functionality required'
        # Duplicate ports
        elif info[idx]['MessageId'] == 'iBMC.1.0.PortIdModificationFailed':
            info[idx]['Message'] = "%s %s" % (
                info[idx]['RelatedProperties'][0].split('#/')[-1],
                'operation failed due to conflict port id')
        # The attribute value is out of range
        elif info[idx]['MessageId'] == 'Base.1.0.PropertyValueNotInList':
            info[idx]['Message'] = "%s %s %s" % (
                'the property',
                info[idx]['RelatedProperties'][0].split('#/')[-1],
                'is out of range')
        # The attribute value type is incorrect.
        elif info[idx]['MessageId'] == 'Base.1.0.PropertyValueTypeError':
            info[idx]['Message'] = "%s %s %s" % (
                'the property',
                info[idx]['RelatedProperties'][0].split('#/')[-1],
                'type invalid')
        else:
            pass

        prt_err(flag, info[idx]['Message'])

    return result_flag


def check_result(resp):
    """
    Function Description:Check the setting results.
    Parameter:resp dict:redfish value
    """
    err_message = ''

    if resp is None:
        return None
    if resp['status_code'] == REDFISH_STATUS_CODE_200:
        # Traverse keys. If errormessage exists, display error messages.
        for key in resp['resource']:
            if key == '@Message.ExtendedInfo':
                err_message = resp['resource'][key]

    # Traverse keys, and display error messages.
    elif resp['status_code'] == REDFISH_STATUS_CODE_400 \
            or resp['status_code'] == REDFISH_STATUS_CODE_501:
        for key in resp['message']['error']:
            if key == '@Message.ExtendedInfo':
                err_message = resp['message']['error'][key]

    else:
        err_message = None

    result_flag = print_err_message(err_message)
    if not result_flag and resp['status_code'] == REDFISH_STATUS_CODE_200:
        sys.exit(UREST_STATUS_CODE_144)

    return resp


def setnetservice(client, args):
    """
    Function Description:Setting Network Service Information
    Parameter:client refishClient:class object
    args object:CLI command
    """
    # Parameter check
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/NetworkProtocol" % slotid
    resp = client.get_resource(url)
    if resp is None or resp.get("status_code", "") == "":
        return None

    if resp['status_code'] == REDFISH_STATUS_CODE_200:
        payload = init_payload(args)
        resp_patch = client.set_resource(url, payload)
        # Check returned values and returned messages.
        resp = check_result(resp_patch)
    elif resp['status_code'] == REDFISH_STATUS_CODE_404:
        print('Failure: resource was not found')

    return resp


def init_payload(args):
    """
    Function Description: init payload
    Parameter:args object:CLI command
    Return Value: payload dict
    """
    # Combine the request body.
    key = args.Protocol
    payload = {key: {}}
    payload_inner_dic = {common_function.COMMON_KEY: payload}
    oem = {'Oem': payload_inner_dic}
    # If the VNC is used, add a request body for the OEM object;
    # otherwise, add it for payload.
    if key == 'VNC':
        add_payload(args, oem)
        payload = oem
    else:
        add_payload(args, payload)
        # Invoke the set method to set values.
    return payload
