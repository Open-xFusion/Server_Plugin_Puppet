# -*- coding: utf-8 -*-
"""
Function: get_sys_eth.py moudle. This moudle mainly involves the
 querying Host Ethernet Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2020-2021
"""
import sys

from pip._vendor.distlib.compat import raw_input
from scripts.common_function import INPUT_INFO

PRINT_STYLE1 = "%-20s: %s"
PRINT_STYLE2 = " " * 20
PRINT_STYLE3 = "-" * 20
PRINT_STYLE4 = "-" * 40


def getsyseth_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    querying host Ethernet information.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2017.8.7 After Network Port Virtualization Is Enabled,
     Information About All Network Ports Cannot Be Displayed
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('getsyseth',
                                   help='get all system ethernet information')
    sub_parser.add_argument('-PA', dest='PAGE',
                            choices=['Enabled', 'Disabled'],
                            required=False,
                            help='get system ethernet '
                                 'information paging display')
    sub_parser.add_argument('-I', dest='ID', required=False,
                            help='get specify system ethernet information')
    parser_dict['getsyseth'] = sub_parser

    return 'getsyseth'


def continue_or_break():
    """
    Function Description:Determine whether to continue or exit.
    Modify: 2019.5.17 the pagination interaction method is optimized.
    Return Value:tmp str:result of the redfish interface
    """
    strtemp = raw_input(INPUT_INFO).strip()
    print(PRINT_STYLE4)
    tmp = strtemp.replace('\r', '')
    if tmp == 'q':
        return None
    return tmp


def get_ipv4addresses(dict1):
    """
    #==========================================================================
    # @Method: Export IPv4 address information functions.
    # @Param: dict1, dictionary
    # @Return:
    # @date: 2017.7.27
    #==========================================================================
    """
    # Obtain IPv4 address information.
    print("[IPv4Addresses]")
    length_ipv4 = len(dict1['IPv4Addresses'])
    if length_ipv4 != 0:
        for i in range(length_ipv4):
            if length_ipv4 > 1:
                print(PRINT_STYLE3)
            print(PRINT_STYLE1 %
                  ("Address", dict1["IPv4Addresses"][i]["Address"]))
            print(PRINT_STYLE1 %
                  ("SubnetMask", dict1["IPv4Addresses"][i]["SubnetMask"]))
            print(PRINT_STYLE1 %
                  ("Gateway", dict1["IPv4Addresses"][i]["Gateway"]))
    if length_ipv4 > 1:
        print(PRINT_STYLE3)
    print(PRINT_STYLE2)


def get_ipv6addresses(dict1):
    """
    #==========================================================================
    # @Method: Query IPv6 address information functions.
    # @Param: dict1, dictionary
    # @Return:
    # @date: 2017.7.27
    #==========================================================================
    """
    # Obtain IPv6 address information.
    print("[IPv6Addresses]")
    length_ipv6 = len(dict1['IPv6Addresses'])
    if length_ipv6 != 0:
        for j in range(length_ipv6):
            if length_ipv6 > 1:
                print(PRINT_STYLE3)
            print(PRINT_STYLE1 %
                  ("Address", dict1["IPv6Addresses"][j]["Address"]))
            print(PRINT_STYLE1 %
                  ("PrefixLength", dict1["IPv6Addresses"][j]["PrefixLength"]))
            print(PRINT_STYLE1 %
                  ("DefaultGateway", dict1["IPv6DefaultGateway"]))
    if length_ipv6 > 1:
        print(PRINT_STYLE3)
    print(PRINT_STYLE2)


def get_vlans(url, client):
    """
    Function Description:Query VLAN information functions.
    Parameter:url str:url
    client refishClient: class object
    Modify: 2017.8.7 After Network Port Virtualization Is Enabled,
    Information About All Network Ports Cannot Be Displayed
    Return Value: resp_vlans dict:result of the redfish interface
    """
    print("[VLANs]")
    url1 = "%s/VLANs" % url
    resp_vlans = client.get_resource(url1)
    if resp_vlans is None or resp_vlans['status_code'] != 200:
        return resp_vlans
    dict_vlans = resp_vlans['resource']
    get_vlans_collection(dict_vlans, client)
    while "Members@odata.nextLink" in dict_vlans:
        url2 = dict_vlans["Members@odata.nextLink"]
        resp_vlans_coll = client.get_resource(url2)
        if resp_vlans_coll is None:
            return None
        dict_vlans = resp_vlans_coll['resource']
        length_vlans1 = len(dict_vlans["Members"])
        if length_vlans1 == 1:
            print(PRINT_STYLE3)
        get_vlans_collection(dict_vlans, client)
        if length_vlans1 == 1:
            print(PRINT_STYLE3)
    return resp_vlans


def get_eth_collection(dict_ids, client, args):
    """
    Function Description:querying Ethernet collection functions.
    Parameter: dict_ids dict: URL's dictionary set.
    client refishClient: class object
    args object:CLI command
    Modify: 2017.8.7 After Network Port Virtualization Is Enabled,
    Information About All Network Ports Cannot Be Displayed
    Return Value: resp_id dict:result of the redfish interface
    """
    resp_id = None
    for i in dict_ids["Members"]:
        url = i["@odata.id"]
        resp_id = client.get_resource(url)
        if resp_id is None:
            return None
        if resp_id['status_code'] == 200:
            dict_id = resp_id['resource']
            # Invoke the get_single_eth_info function.
            get_single_eth_info(url, dict_id, client)
            if (dict_ids["Members@odata.count"]) > 1:
                print(PRINT_STYLE4)
        if args.PAGE == 'Enabled':
            tmp = continue_or_break()
            if tmp is None:
                sys.exit(0)

    return resp_id


def get_vlans_collection(dict_vlans, client):
    """
    Function Description:Querying VLAN collection functions.
    Parameter:dict_vlans dict: vlans's infomation
    client refishClient: class object
    Modify: 2017.8.7 After Network Port Virtualization Is Enabled,
    Information About All Network Ports Cannot Be Displayed
    """
    print_style1 = "%-20s: %-4s  %s  %s"
    length_vlans2 = len(dict_vlans["Members"])
    for k in dict_vlans["Members"]:
        url2 = k["@odata.id"]
        resp_vlan = client.get_resource(url2)
        if resp_vlan is None or resp_vlan['status_code'] != 200:
            break

        dict_vlan = resp_vlan['resource']
        if length_vlans2 > 1:
            print(PRINT_STYLE3)
        if dict_vlan["VLANEnable"] == "true":
            dict_vlan["VLANEnable"] = "enabled"
        else:
            dict_vlan["VLANEnable"] = "disabled"
        print(print_style1 %
              ("VLAN", dict_vlan["VLANId"], "|", dict_vlan["VLANEnable"]))
    if length_vlans2 > 1 and "Members@odata.nextLink" not in dict_vlans:
        print(PRINT_STYLE3)


def get_eth_info_id(ethid, slotid, client):
    """
    #==========================================================================
    # @Method: Query host Ethernet information with IDs.
    # @Param: ethid, slotid, client
    # @Return:
    # @date: 2017.7.27
    #==========================================================================
    """
    url = "/redfish/v1/Systems/%s/EthernetInterfaces/%s" % (slotid, ethid)
    resp = client.get_resource(url)
    if resp is None:
        return None

    # Determine the entered ID.
    if resp['status_code'] == 404:
        print("Failure: resource was not found")
    elif resp['status_code'] == 200:
        dict1 = resp['resource']
        # Invoke the get_single_eth_info function.
        get_single_eth_info(url, dict1, client)

    return resp


def get_eth_info(slotid, client, args):
    """
    Function Description:Querying host Ethernet information without IDs
    Parameter:slotid str: slot number
    client refishClient: class object
    args object:CLI command
    Modify: 2017.8.7 After Network Port Virtualization Is Enabled,
    Information About All Network Ports Cannot Be Displayed
    Return Value: resp dict: result of the redfish interface
    """
    url1 = "/redfish/v1/Systems/%s/EthernetInterfaces" % slotid
    resp = client.get_resource(url1)
    if resp is None:
        return None

    resp_ids = client.get_resource(url1)
    if resp_ids is None:
        return None

    if resp['status_code'] == 200:
        dict_ids = resp['resource']
        # Determine whether the ID collection is zero.
        if dict_ids["Members@odata.count"] == 0:
            print("no data available for the resource")
            return resp
        resp = get_next_link(args, client, resp)
    return resp


def get_next_link(args, client, resp):
    """
    功能描述：获取 Members@odata.nextLink 对应链接url的结果
    参数：args （list）：CLI命令
         client (redfish_client）:请求redfish客户端对象
         resp (dict):通过"/redfish/v1/Systems/1/EthernetInterfaces"
           请求回来的redfish结果
    返回值：resp_one (dict):最后一个Member 的redfish接口请求结果
    """
    dict_ids = resp['resource']
    resp = get_eth_collection(dict_ids, client, args)
    if resp is None:
        return None
    while "Members@odata.nextLink" in dict_ids:
        url2 = dict_ids["Members@odata.nextLink"]
        resp_ids_coll = client.get_resource(url2)
        if resp_ids_coll is not None:
            dict_ids = resp_ids_coll['resource']
            resp = get_eth_collection(dict_ids, client, args)
            if resp is None:
                return None
    return resp


def get_single_eth_info(url, dict1, client):
    """
    #==========================================================================
    # @Method: Export host Ethernet information functions.
    # @Param: url
              dict1, dictionary
              client, RedfishClient object
    # @Return:
    # @date: 2017.7.27
    #==========================================================================
    """
    print(PRINT_STYLE1 % ("Id", dict1["Id"]))

    if "MACAddress" in list(dict1.keys()):
        print(PRINT_STYLE1 % ("MACAddress", dict1["MACAddress"]))
    if "PermanentMACAddress" in list(dict1.keys()):
        print(PRINT_STYLE1 %
              ("PermanentMACAddress", dict1["PermanentMACAddress"]))

    print(PRINT_STYLE1 % ("LinkStatus", dict1["LinkStatus"]))
    print(PRINT_STYLE2)
    get_ipv4addresses(dict1)
    get_ipv6addresses(dict1)
    get_vlans(url, client)


def getsyseth(client, args):
    """
    Function Description:querying host Ethernet information.
    Parameter:client refishClient: class object
    args object:CLI command
    Modify: 2017.8.7 After Network Port Virtualization Is Enabled,
    Information About All Network Ports Cannot Be Displayed
    Return Value: resp dict: result of the redfish interface
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None

    if args.ID is not None:
        resp = get_eth_info_id(args.ID, slotid, client)
    else:
        resp = get_eth_info(slotid, client, args)

    return resp
