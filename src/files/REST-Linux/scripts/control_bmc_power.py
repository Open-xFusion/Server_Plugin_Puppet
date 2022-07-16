#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
#=========================================================================
#   @Description:  control fru power
#
#   @Date:
#=========================================================================
'''
import upgrade_sp


def controlbmcpower_init(parser, parser_list):
    '''
    #=====================================================================
    #   @Description:  control bmc power subcommand init
    #   @Method:  controlbmcpower_init
    #   @Param:
    #   @Return:
    #   @Date:
    #=====================================================================
    '''
    sub_parser = parser.add_parser('bmcpowerctrl', \
                                   help='''bmc power control''')
    parser_list['bmcpowerctrl'] = sub_parser
    return 'bmcpowerctrl'


def controlbmcpower(client, args):
    '''
    #====================================================================
    #   @Description:  control BMC power entry
    #   @Method:  postbmcpower
    #   @Param:
    #   @Return:
    #   @Date:
    #====================================================================
    '''
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Managers/%s/Actions/Manager.Reset" % slotid 
    payload = {"ResetType": "ForceRestart"}
    resp = client.create_resource(url, payload)
    if resp is None:
        return None

    if resp.get('status_code') == 200:
        print('Success: successfully completed request')

    else:
        if resp.get('status_code') == 400:
            msg = resp['message']['error']['@Message.ExtendedInfo'] \
                [0]['Message']
            print('Failure:' + msg)
        else:
            upgrade_sp.print_status_code(resp)

    return resp
