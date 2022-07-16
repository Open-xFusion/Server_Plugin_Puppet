# -*- coding:utf-8 -*-
"""
Function: get_cpu.py moudle. This moudle mainly involves the
 querying information about the cpu resource of a server function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2021
"""
from scripts.common_function import CustomError
from scripts import common_function

PRO_FORMAT = '%-25s: %s'


def get_cpu_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    querying information about the cpu resource of a server function.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    """
    sub_parser = parser.add_parser('getcpu',
                                   help='''get processor information''')
    parser_dict['getcpu'] = sub_parser

    return 'getcpu'


def get_processor(client, processor_url):
    """
    #==========================================================================
    # @Method: Query specified memory information.
    # @Param: client
    # @Return:
    #==========================================================================
    """
    processor_resp = client.get_resource(processor_url)
    if processor_resp is None:
        raise CustomError(common_function.RESOURCE_NULL)
    if processor_resp['status_code'] == 200:
        key = processor_resp['resource']
        if key.get('ProcessorType', None) != "CPU":
            return processor_resp

        print('-' * 50)
        print(PRO_FORMAT % ('Id', key.get("Id", None)))
        print(PRO_FORMAT % ('Name', key.get('Name', None)))
        if key.get("Oem") is not None:
            vendor_dict = common_function.get_vendor_value(processor_resp)
            print(PRO_FORMAT % ("Position", vendor_dict.get("Position")))
            for oem_key, value in vendor_dict.items():
                if oem_key == "Position":
                    continue
                print(PRO_FORMAT % (oem_key, value))
        print(PRO_FORMAT % ('ProcessorType',
                            key.get('ProcessorType', None)))
        print(PRO_FORMAT % ('ProcessorArchitecture',
                            key.get('ProcessorArchitecture', None)))
        print(PRO_FORMAT % ('InstructionSet',
                            key.get('InstructionSet', None)))
        print(PRO_FORMAT % ('Manufacturer',
                            key.get('Manufacturer', None)))
        print(PRO_FORMAT % ('Model', key.get('Model', None)))
        print(PRO_FORMAT % ('MaxSpeedMHz',
                            key.get('MaxSpeedMHz', None)))
        print(PRO_FORMAT % ('TotalCores',
                            key.get('TotalCores', None)))
        print(PRO_FORMAT % ('TotalThreads',
                            key.get('TotalThreads', None)))
        print(PRO_FORMAT % ('Socket', key.get('Socket', None)))
        print('\n[Status]')
        if key.get("Status", None) is not None:
            print(PRO_FORMAT % ('Health',
                                key['Status'].get('Health', None)))
            print(PRO_FORMAT % ('State',
                                key['Status'].get('State', None)))

        print('\n[ProcessorId]')
        if key.get("ProcessorId", None) is not None:
            print(PRO_FORMAT %
                  ('IdentificationRegisters',
                   key['ProcessorId'].get('IdentificationRegisters', None)))

    return processor_resp


def get_processor_collection(client):
    """
    #==========================================================================
    # @Method: Query CPU collection information.
    # @Param: client
    # @Return:
    #==========================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        raise CustomError(common_function.SLOT_ID_ERROR)
    url = "/redfish/v1/Systems/%s/Processors/" % slotid
    collection_resp = client.get_resource(url)
    if collection_resp['status_code'] != 200:
        return collection_resp
    count = 0
    while count < collection_resp['resource']['Members@odata.count']:
        get_resp = get_processor(client,
                                 collection_resp['resource']['Members'][count][
                                     '@odata.id'])
        if get_resp['status_code'] != 200:
            return get_resp
        count += 1
    return get_resp


def get_cpu_summary(client):
    """
    #==========================================================================
    # @Method: Query system resource CPU information.
    # @Param: client
    # @Return:
    # @Modify: 2019.01.22
    #==========================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        raise CustomError(common_function.SLOT_ID_ERROR)
    url = "/redfish/v1/Systems/%s/" % slotid
    sys_resp = client.get_resource(url)
    if sys_resp is None:
        raise CustomError(common_function.RESOURCE_NULL)
    if sys_resp['status_code'] == 200:
        print('-' * 50)
        print(PRO_FORMAT % ('Count',
                            sys_resp['resource']['ProcessorSummary']['Count']))
        print(PRO_FORMAT % ('Model',
                            sys_resp['resource']['ProcessorSummary']['Model']))
        print('\n[Status]')
        print(PRO_FORMAT %
              ('HealthRollup',
               sys_resp['resource']['ProcessorSummary']['Status'][
                   'HealthRollup']))
    return sys_resp


def get_cpu(client, _):
    """
    #==========================================================================
    # @Method: Obtain CPU information command processing functions.
    # @Param: client, RedfishClient object
    parser, subcommand argparser.
    Export error messages when parameters are incorrect.
    args, parameter list
    # @Return:
    #==========================================================================
    """
    resp = get_cpu_summary(client)

    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
        return resp
    resp = get_processor_collection(client)
    if resp['status_code'] == 200:
        print('-' * 50)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
        return resp
    return resp
