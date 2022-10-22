#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Function:Delete license
Date:2019.01.18
"""
from common_function import change_message
from common_function import CustomError
from common_function import SLOT_ID_ERROR
from common_function import RESOURCE_NULL


def deletelicense_init(parser, parser_list):
    """
    :Function:Install license subcommand
    :param parser:major command argparser
    :param parser_list:save subcommand parser list
    :return:
    """
    sub_parser = parser.add_parser('deletelicense', help='delete license')
    parser_list['deletelicense'] = sub_parser
    return 'deletelicense'


def deletelicense(client, args):
    """
    :Function:Install license
    :param client:RedfishClient object
    :param parser:subcommand argparser. Export error messages when parameters are incorrect.
    :param args:parameter list
    :return:
    """
    # Obtain the slot number.
    slotid = client.get_slotid()
    if slotid is None:
        raise CustomError(SLOT_ID_ERROR)

    url = "/redfish/v1/Managers/%s/LicenseService" \
          "/Actions/LicenseService.DeleteLicense" % slotid
    resp = client.create_resource(url, {})

    if resp is None:
        raise CustomError(RESOURCE_NULL)

    status_code = resp['status_code']
    if status_code == 200:
        print('Success: successfully completed request')
    elif status_code == 404:
        print('Failure: resource was not found')
    elif status_code < 500:
        messages = resp['message']['error']['@Message.ExtendedInfo']
        if messages is None or len(messages) == 0:
            raise CustomError("Message in resp is null.")

        message = messages[0]
        print(message)
        failure = change_message(message['Message'])
        resolution = message['Resolution']
        print('Failure: %s; Resolution: %s.' % (failure, resolution))
    else:
        print("Failure: the request failed due to an internal service error")

    return resp
