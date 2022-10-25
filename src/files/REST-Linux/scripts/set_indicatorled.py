# -*- coding:utf-8 -*-

"""
#=========================================================================
#   @Description:  Set indicator State of Chassis
#
#   @author:
#   @Date:
#=========================================================================
"""
import sys
from common_function import CustomError
from common_function import SLOT_ID_ERROR
from common_function import RESOURCE_NULL


def setindicatorled_init(parser, parser_list):
    """
    #=====================================================================
    #   @Method:  set indicator LED state
    #   @Param:
    #   @Return:
    #   @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('setindicatorled',
                                   help='''set product information''')
    sub_parser.add_argument('-S', dest='state', required=True,
                            choices=['Lit', 'Off', 'Blinking'],
                            help='state of indicator led')

    parser_list['setindicatorled'] = sub_parser
    return 'setindicatorled'


def setindicatorled(client, args):
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
        raise CustomError(SLOT_ID_ERROR)

    url = "/redfish/v1/Chassis/%s" % slotid

    resp = client.get_resource(url)
    if resp is None:
        raise CustomError(RESOURCE_NULL)
    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
        return resp

    payload = {
        "IndicatorLED": args.state
    }

    resp = client.set_resource(url, payload)
    if resp is None:
        raise CustomError(RESOURCE_NULL)

    if resp['status_code'] == 200:
        print('Success: successfully completed request')
    else:
        from common_function import change_message
        messages = resp['message']['error']['@Message.ExtendedInfo']
        if messages is None or len(messages) == 0:
            raise CustomError("Message in resp is null.")

        message = messages[0]
        print(message)
        failure = change_message(message['Message'])
        resolution = message['Resolution']
        print('Failure: %s; Resolution: %s.' % (failure, resolution))

    return resp
