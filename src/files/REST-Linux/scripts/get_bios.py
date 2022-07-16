# -*- coding:utf-8 -*-
"""
Function: get_bios.py moudle. This moudle mainly involves the
 querying BIOS Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
import sys

from scripts import common_function


def getbios_init(parser, parser_list):
    """
    #=====================================================================
    #   @Method:  BIOS menu item query subcommands
    #   @Param:   parser, major command argparser
    #                    parser_list, save subcommand parser list
    #   @Return:
    #   @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('getbios',
                                   help='''get BIOS setup information''')
    sub_parser.add_argument('-A', dest='attribute',
                            required=False,
                            help='''attribute name''')

    parser_list['getbios'] = sub_parser

    return 'getbios'


def getbios(client, args):
    """
    #=====================================================================
    #   @Method: BIOS menu item query subcommand processing functions
    #   @Param:  client, RedfishClient object
                 args, parameter list
    #   @Return:
    #   @author:
    #   @date:  2017-8-30 09:04:14
    #=====================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Systems/%s/Bios" % slotid
    resp = client.get_resource(url)
    if resp is None:
        return None

    if resp['status_code'] == 200:
        info = resp['resource']['Attributes']
        if info is None:
            print('no data available for the resource')
            return resp

        print_resource(info, args)

    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
    else:
        common_function.print_status_code(resp)

    return resp


def print_resource(info, args):
    """
    Function Description:Displaying the returned BIOS data.
    Parameter:info dict: BIOS message dictionary
    args object:CLI command
    Modify: 2018.11.30 Modify the prompt when the -A parameter does not exist
    """
    if args.attribute is not None:
        # Display data specified by parameters.
        if args.attribute in info:
            # Modify: 2019.7.19 Configuring the BIOS Parameters BMCWDTTimeout.
            if args.attribute == "BMCWDTTimeout" \
                    and int(info[args.attribute]) < 15:
                info[args.attribute] = str(int(info[args.attribute]) + 15)
            print("-" * 70)
            print("%-42s%-2s%-s" % (args.attribute, ":", info[args.attribute]))
            print("-" * 70)
        else:
            print('Failure: attribute not found')
            sys.exit(common_function.UREST_STATUS_CODE_2)
    else:
        print("-" * 70)
        for key in info:
            # Modify: 2019.7.19 Configuring the BIOS Parameters BMCWDTTimeout.
            if key == "BMCWDTTimeout" and int(info[key]) < 15:
                info[key] = str(int(info[key]) + 15)
            print("%-42s%-2s%-s" % (key, ":", info[key]))

        print("-" * 70)
