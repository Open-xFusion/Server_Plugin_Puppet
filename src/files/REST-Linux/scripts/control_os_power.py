# -*- coding: utf-8 -*-
"""
Function: control_os_power.py moudle. This moudle mainly involves the
 powering On or Off an OS function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
from scripts import common_function


def controlospower_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    powering On or Off an OS.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('syspowerctrl',
                                   help='''system power control''')
    sub_parser.add_argument('-T', dest='ResetType',
                            choices=['On', 'ForceOff', 'GracefulShutdown',
                                     'ForceRestart', 'Nmi', 'ForcePowerCycle'],
                            required=True,
                            help='''system power control options''')
    parser_dict['syspowerctrl'] = sub_parser

    return 'syspowerctrl'


def controlospower(client, args):
    """
    #=========================================================================
    #   @Description:  control os power entry
    #   @Method:  controlospower
    #   @Param:
    #   @Return:
    #   @Date:
    #=========================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/systems/%s/Actions/ComputerSystem.Reset" % slotid

    payload = {"ResetType": args.ResetType}

    resp = client.create_resource(url, payload)
    if resp is None:
        return None

    if resp['status_code'] == 200:
        print('Success: successfully completed request')

    else:
        if resp['status_code'] == 400:
            print('Failure: operation not allowed')
        else:
            common_function.print_status_code(resp)

    return resp
