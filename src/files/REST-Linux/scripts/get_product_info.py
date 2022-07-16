# -*- coding:utf-8 -*-
"""
Function: get_product_info.py moudle. This moudle mainly involves the
 querying Information of the Entire System function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
from scripts import common_function


def getproductinfo_init(parser, parser_list):
    """
    #=====================================================================
    #  @Method: get product information
    #  @Param:
    #  @Return:
    #  @author:
    #=====================================================================
    """
    sub_parser = parser.add_parser('getproductinfo',
                                   help='''get product information''')

    parser_list['getproductinfo'] = sub_parser

    return 'getproductinfo'


def getproductinfo(client, _):
    """
    #=====================================================================
    #   @Method: get product information
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

    if resp['status_code'] == 200:
        print_resource(resp)

    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
    else:
        print("Failure: the request failed due to an internal service error")

    return resp


def print_resource(resp):
    """
    #=====================================================================
    #   @Method:  print information
    #   @Param:
    #   @Return:
    #   @author:
    #=====================================================================
    """
    info = resp['resource']
    print("%-18s%-2s%-s" % ("Name", ":", info['Name']))
    print("%-18s%-2s%-s" % ("AssetTag", ":", info['AssetTag']))
    print("%-18s%-2s%-s" % ("Manufacturer", ":", info['Manufacturer']))
    print("%-18s%-2s%-s" % ("Model", ":", info['Model']))
    print("%-18s%-2s%-s" % ("SerialNumber", ":", info['SerialNumber']))
    print("%-18s%-2s%-s" % ("UUID", ":", info['UUID']))
    print("%-18s%-2s%-s" % ("HostName", ":", info['HostName']))
    vendor_dict = common_function.get_vendor_value(resp)
    print("%-18s%-2s%-s" % ("ProductAlias", ":",
                            vendor_dict['ProductAlias']))
    print("%-18s%-2s%-s" % ("ProductVersion", ":",
                            vendor_dict['ProductVersion']))
    print("%-18s%-2s%-s" % ("HostingRole", ":", ','.join(info['HostingRole'])))
    print("%-18s%-2s%-s" % ("BiosVersion", ":", info['BiosVersion']))
    print("%-18s%-2s%-s" % ("DeviceOwnerID", ":",
                            vendor_dict['DeviceOwnerID']))
    print("%-18s%-2s%-s" % ("DeviceSlotID", ":",
                            vendor_dict['DeviceSlotID']))

    print("%-18s%-2s%-s" % ("PowerState", ":", info['PowerState']))
    print("\r\n%-18s" % "[Status]")
    print("%-18s%-2s%-s" % ("State", ":", info['Status']['State']))
    print("%-18s%-2s%-s" % ("Health", ":", info['Status']['Health']))
