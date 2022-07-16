# -*- coding:utf-8 -*-
"""
Function: set_product_info.py moudle. This moudle mainly involves the
 setting Information of the Entire System function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
import sys
from scripts import common_function


def setproductinfo_init(parser, parser_list):
    """
    #=====================================================================
    #   @Method:  set product information
    #   @Param:
    #   @Return:
    #   @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('setproductinfo',
                                   help='''set product information''')
    sub_parser.add_argument('-Tag', dest='assettag', required=False,
                            help='asset tag. it cannot exceed 48 characters. '
                                 'use quotation marks (") to enclose special '
                                 'characters')

    sub_parser.add_argument('-Al', dest='productalias', required=False,
                            help='product alias. it cannot exceed 60 '
                                 'characters. use quotation marks (") to '
                                 'enclose special characters')

    parser_list['setproductinfo'] = sub_parser

    return 'setproductinfo'


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if not (args.assettag or args.productalias):
        parser.error('at least one parameter must be specified')


def setproductinfo(client, args):
    """
    #=====================================================================
    #   @Method:  set product info
    #   @Param:
    #   @Return:
    #   @author:
    #=====================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    url = "/redfish/v1/Systems/%s" % slotid

    resp = client.get_resource(url)
    if resp is None:
        return None
    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
        return resp

    payload = {}
    if args.assettag:
        payload["AssetTag"] = args.assettag
    if args.productalias:
        payload["Oem"] = {
            common_function.COMMON_KEY: {
                "ProductAlias": args.productalias
            }
        }

    resp = client.set_resource(url, payload)
    if resp is None:
        return None

    if resp['status_code'] == 200:
        # Some settings are incorrect.
        if resp['resource'].get('@Message.ExtendedInfo'):
            messages = resp['resource']['@Message.ExtendedInfo']
            _printferrormessages(1, messages)
            sys.exit(144)
        else:
            print('Success: successfully completed request')

    else:
        if resp['status_code'] == 400:
            messages = resp['message']['error']['@Message.ExtendedInfo']
            _printferrormessages(0, messages)

    return resp


def _printferrormessages(k, msgs):
    """
    #=========================================================================
    #   @Description:  _printf error messages
    #   @Method:  _printferrormessages
    #   @Param:
    #   @Return:
    #   @author:
    #   @Date:
    #=========================================================================
    """
    # Insufficient permission
    for msginfo in msgs:
        if msginfo['MessageId'].split('.')[-1] == \
                "PropertyModificationNeedPrivilege":
            print('Failure: you do not have the required permissions to '
                  'perform this operation')
            return

            # Other errors
    if k == 1:
        error = 'Failure: some of the settings failed. '
        error = error + 'possible causes include the following:'
        print(error)
        for msg_info in msgs:
            len_msg = len(msg_info['RelatedProperties'])
            if len_msg == 0:
                msg = msg_info['MessageArgs'][1]
            else:
                msg = msg_info['RelatedProperties'][0].split('/')[-1]
            print('         invalid property %s value' % msg)

    if k == 0:
        for i in range(k, len(msgs)):
            len_msg = len(msgs[i]['RelatedProperties'])
            if len_msg == 0:
                msg = msgs[i]['MessageArgs'][1]
            else:
                msg = msgs[i]['RelatedProperties'][0].split('/')[-1]
            if i == 0:
                print('Failure: invalid property %s value' % msg)
            else:
                print('         invalid property %s value' % msg)
