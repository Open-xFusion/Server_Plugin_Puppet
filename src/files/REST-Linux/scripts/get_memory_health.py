# -*- coding:utf-8 -*-
'''
#==========================================================================
# @Method: Query memory information.
# @command: getmemoryhealth
# @Param: 
# @author: 
# @date: 2017.7.21
#==========================================================================
'''
MEM_FORMAT = '%-25s: %s'


def getmemoryhealth_init(parser, parser_list):
    '''
    #====================================================================================
    # @Method:  Register and obtain memory commands.
    # @Param: parser, major command argparser
    parser_list, save subcommand parser list
    # @Return:
    # @author: 
    #====================================================================================
    '''
    sub_parser = parser.add_parser('getmemoryhealth',
                                   help='''get memory information''')
    parser_list['getmemoryhealth'] = sub_parser

    return 'getmemoryhealth'


def get_memory(client, memory_url):
    '''
    #====================================================================================
    # @Method: Query specified memory information.
    # @Param: client，memory_url
    # @Return:
    # @author: 
    #====================================================================================
    '''
    memory_resp = client.get_resource(memory_url)
    if memory_resp is None:
        return None
    if memory_resp['status_code'] == 200:
        print('-' * 35)
        key = memory_resp['resource']
        print(MEM_FORMAT % ('DeviceLocator', \
                              key.get('DeviceLocator', None)))
        status = key.get('Status', {})
        print(MEM_FORMAT % ('Health', status.get('Health', None)))
        print(MEM_FORMAT % ('State', status.get('State', None)))
    return memory_resp


def get_memory_collection(client):
    """
    #====================================================================================
    # @Method: Query memory collection information.
    # @Param: client
    # @Return:
    # @author: 
    #====================================================================================
    """
    slotid = client.get_slotid()
    if slotid is None:
        return None
    url = "/redfish/v1/Systems/%s/Memory/" % slotid
    collection_resp = client.get_resource(url)
    if collection_resp is None:
        return None
    if collection_resp['status_code'] != 200:
        return collection_resp
    count = 0
    while count < collection_resp['resource']['Members@odata.count']:
        get_resp = get_memory(client,
                              collection_resp['resource']['Members'][count]['@odata.id'])
        if get_resp['status_code'] != 200:
            return get_resp
        count += 1
    return collection_resp


def get_memory_sys(client):
    '''
    #====================================================================================
    # @Method: Query system resource memory information.
    # @Param: client
    # @date: 2017.8.1 11:09
    #====================================================================================
    '''
    slotid = client.get_slotid()
    if slotid is None:
        return None
    url = "/redfish/v1/Systems/%s/" % slotid
    sys_resp = client.get_resource(url)
    if sys_resp is None:
        return None
    if sys_resp['status_code'] == 200:
        print('-' * 35)
        print('[Summary]')
        status = sys_resp['resource']['MemorySummary']['Status']
        print(MEM_FORMAT % ('HealthRollup', status['HealthRollup']))
    return sys_resp


def getmemoryhealth(client, args):
    '''
    #====================================================================================
    # @Method: Obtain memory information command processing functions.
    # @Param: client, RedfishClient object
    parser, subcommand argparser. Export error messages when parameters are incorrect.
    args, parameter list
    # @Return:
    # @author: 
    #====================================================================================
    '''
    resp = get_memory_sys(client)
    if resp is None:
        return None
    if resp['status_code'] != 200:
        if resp['status_code'] == 404:
            print('Failure: resource was not found')
        return resp
    resp = get_memory_collection(client)
    if resp is None:
        return None
    if resp['status_code'] == 200:
        print('-' * 35)
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
        return resp
    return resp
