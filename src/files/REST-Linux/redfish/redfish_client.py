# -*- coding:utf-8 -*-
"""
Function: redfish_client.py moudle. This moudle mainly involves
 accessing the Redfish Interface function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2021
"""
import json
import re
import sys
import time
import ssl
import traceback

from decimal import Decimal
from scripts.common_function import UREST_STATUS_CODE_2
from scripts.common_function import REDFISH_STATUS_CODE_412
from scripts.common_function import UREST_STATUS_CODE_156
from scripts.common_function import CustomError
from scripts.common_function import REDFISH_STATUS_CODE_200
from scripts import common_function

old_task_percent = "0%"

try:
    import requests
    from requests.exceptions import Timeout, SSLError
except ImportError as e:
    print(e)
    sys.exit(127)

PRINT_FORMAT = '%-17s%-2s%-20s'
# Added subcommands that support local export.
flag_state = ['collectsel', 'config', 'exportcsr', 'getdiaginfo',
              'getscreenshot', 'upgradefw']
# Modify:2020.3.20 代码检视问题：upgradefw放入列表，方便后续扩展
sub_command = None
re_session_command = ["upgradefw"]

try:
    from requests.packages.urllib3.connection import\
        HTTPSConnection as HTTPSConnection
    from requests.packages.urllib3.util.retry import Retry
    from ssl import PROTOCOL_TLSv1_2
    from requests.packages.urllib3 import PoolManager
    from requests.adapters import HTTPAdapter

    IMPORT_TLS = True
except ImportError:
    IMPORT_TLS = False

if IMPORT_TLS:
    class HostNameIgnoringAdapter(HTTPAdapter):
        """
        Function Description:connection adapter
        Interface:requests.adapters.HTTPAdapter
        """
        ssl._DEFAULT_CIPHERS = (
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
            "DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES256-GCM-SHA384:"
            "ECDHE-RSA-CHACHA20-POLY1305")

        def __init__(self):
            retry = Retry(total=3, connect=3, backoff_factor=0.5)
            super(HostNameIgnoringAdapter, self).__init__(max_retries=retry)

        def init_poolmanager(self, *pool_args, **pool_kwargs):
            if "ssl_context" in dir(HTTPSConnection(host="")):
                context = ssl.SSLContext(PROTOCOL_TLSv1_2)
                context.set_ciphers(ssl._DEFAULT_CIPHERS)
                self.poolmanager = PoolManager(*pool_args,
                                               assert_hostname=False,
                                               ssl_version=PROTOCOL_TLSv1_2,
                                               ssl_context=context,
                                               **pool_kwargs)
            else:
                self.poolmanager = PoolManager(*pool_args,
                                               assert_hostname=False,
                                               ssl_version=PROTOCOL_TLSv1_2,
                                               **pool_kwargs)


def is_task_progress_max(progress, ref_progress):
    """
    Function Description:The current progress is greater than or
     equal to the progress before ref_progress.
    Parameter:progress str: the current progress
    ref_progress str: the before progress
    Return Value: bool
    """
    re_progress = r"^[\d]+\.{0,1}[\d]*%$"
    return (re.match(re_progress, progress, re.I)
            and re.match(re_progress, ref_progress, re.I)
            and is_max_progress(progress, ref_progress))


def is_max_progress(progress, ref_progress):
    """
    Function Description:The current progress is greater than or
    equal to the progress before ref_progress.
    Parameter:progress str: the current progress
    ref_progress str: the before progress
    Return Value: bool
    """
    progress = progress.replace("%", "")
    ref_progress = ref_progress.replace("%", "")
    progress = Decimal(progress)
    ref_progress = Decimal(ref_progress)
    return progress >= ref_progress


def error_info_check(r):
    """
    check error information
    :param r:
    :return:
    """
    ret = {'status_code': r.status_code,
           'message': json.loads(r.content.decode('utf8', 'ignore')),
           'headers': r.headers}
    try:
        message = ret['message']['error']['@Message.ExtendedInfo'][0][
            'Message']
        print("Failure: %s" % message)
    except (KeyError, IndexError):
        print('Failure: status code ' + str(ret['status_code']))


def set_exit_code(resp):
    """
        exit code
        :param resp:
        :return:
    """
    status_dic = {201: 0, 202: 0, 200: 0, 400: 144, 401: 145, 403: 147,
                  404: 148, 405: 149, 409: 153, 500: 244, 501: 245}
    if resp and resp.get('status_code') is not None:
        status_code = status_dic.get(resp['status_code'])
        sys.exit(status_code)
    else:
        sys.exit(0)


def get_error_info(ret):
    """
    print error information
    :return:
    """
    try:
        message = ret['message']['error']['@Message.ExtendedInfo']
        print("Failure: %s" % message[0]['Message'])
    except (KeyError, IndexError):
        print('Failure: status code ' + str(ret['status_code']))


def err_401_proc(resp):
    """
    Function Description:Processing error 401
    Parameter:resp dict: result of the redfish interface
    Modify: 2018.12.13 Modify the prompt for 'NoValidSession'.
    """
    try:
        ret = {'status_code': resp.status_code,
               'message': resp.json(),
               'headers': resp.headers}

        message_id = \
            ret['message']['error']['@Message.ExtendedInfo'][0][
                'MessageId'].split(".")[3]

        if message_id in ['LoginFailed', 'AuthorizationFailed']:
            error_info = 'user name or password is incorrect,' \
                         ' or your account is locked'
            raise common_function.CustomError(error_info=error_info,
                                              code=ret.get('status_code'))
        elif message_id == 'NoAccess':
            print('Failure: the user gains no access')
            sys.exit(common_function.UREST_INVALID_SESSION_CODE)
        elif message_id == 'UserPasswordExpired':
            print('Failure: password overdued')
            sys.exit(common_function.UREST_INVALID_SESSION_CODE)
        elif message_id == 'UserLoginRestricted':
            print('Failure: login restricted')
            sys.exit(common_function.UREST_INVALID_SESSION_CODE)
        else:
            raise common_function.CustomError(ret)

    except (KeyError, IndexError, AttributeError, ValueError):
        print('Failure: incomplete response from the server')
        sys.exit(common_function.UREST_INVALID_SESSION_CODE)


def print_task_percent(cur_perc, step, task_percent):
    """
    Function Description:urest print percentage
    Parameter:cur_perc int: the current progress
    step int: progress step
    task_percent str: redfish progress
    Return Value: cur_perc int:urest progress
    """
    if task_percent is None:
        task_percent = "%d%%" % int(cur_perc)
        if is_task_progress_max(task_percent, "99%"):
            task_percent = "99%"
        cur_perc = cur_perc + step

    global old_task_percent
    if is_task_progress_max(task_percent, old_task_percent):
        old_task_percent = task_percent
        sys.stdout.write(
            '                                            \r')
        sys.stdout.flush()
        sys.stdout.write("Progress: %s\r" % task_percent)
        sys.stdout.flush()

    return cur_perc


def get_session():
    """
    Function Description:get session
    """
    if not IMPORT_TLS:
        raise common_function.CustomError(
            'Failure: import ssl.PROTOCOL_TLSv1_2'
            ' or PoolManager or'
            ' HTTPAdapter exception.')
    session = requests.session()
    adapter = HostNameIgnoringAdapter()
    session.mount("https://", adapter)
    return session


class RedfishClient:
    """
    REST服务访问接口封装
    """

    def __init__(self):
        """
        Constructor
        """
        self.host = ''
        self.port = ''
        self.username = ''
        self.password = ''
        self.timeout = None
        self.retry_count = 10
        self.retry_sleep_time = 1
        self.retry_flag = True
        self.token = ''
        self.etag = ''
        self.headerhost = None
        self.auth = None
        self.recreate_session_count = 0
        self.cert_path = None
        requests.packages.urllib3.disable_warnings()

    def setself(self, args):
        """
        #=====================================================================
        #   @Method:  设置带内hos，port,username,password值
        #   @Param:
        #   @Return:
        #   @author:
        #=====================================================================
        """
        self.host = args.host
        self.port = args.port
        self.username = args.username
        self.password = args.password
        self.timeout = args.timeout
        self.cert_path = args.cert

    def retry_request(self, resource_info, headers=None, data=None, files=None):
        """
        Function Description:Sending an HTTP request to the RESTful interface.
        Parameter:resource_info str: requesting RESTful resource path.
        data dict:data carried in the request body
        headers dict:data carried in the request header
        files dict:file information
        Return Value: r object:the response object is returned
        """
        error_info = None
        end_count = self.retry_count + 2
        for i in range(1, end_count):
            try:
                r = self.request(resource_info, headers, data, files)
                return r
            except common_function.CustomError as e:
                error_info = e.get_dict()
                if not self.retry_flag:
                    break
                if e.get_dict().get('status_code') == \
                        common_function.INVALID_SESSION_CODE:
                    if self.headerhost is None:
                        break
                    self.create_inner_session()
                time.sleep(self.retry_sleep_time)
                continue

        raise common_function.CustomError(error_info)

    def request(self, resource_info, headers=None, data=None, files=None):
        """
        Function Description:Sending an HTTP request to the RESTful interface.
        Parameter:resource_info str: requesting RESTful resource path.
        data dict:data carried in the request body
        headers dict:data carried in the request header
        files dict:file information
        Modify: 2019.1.16 Optimization request timeout echo  message.
        Return Value: r object:the response object is returned
        """
        method = resource_info[0]
        resource = resource_info[1]
        timeout = resource_info[2]
        default_timeout = timeout
        # If the user sets the timeout parameter and passes the check,
        # the user timeout is set.
        # Otherwise, the default value is used.
        if self.timeout is not None:
            timeout = self.timeout
        headers = self.get_headers(headers)
        if isinstance(data, dict):
            payload = json.dumps(data)
        else:
            payload = data
        url = self.get_url(resource)
        session = get_session()
        try:
            if method == 'POST':
                r = session.post(url, data=payload, files=files,
                                 headers=headers,
                                 auth=self.auth, verify=self.cert_path,
                                 timeout=timeout)
            elif method == 'GET':
                r = session.get(url, data=payload, headers=headers,
                                auth=self.auth, verify=self.cert_path,
                                timeout=timeout)
            elif method == 'DELETE':
                r = session.delete(url, data=payload, headers=headers,
                                   auth=self.auth, verify=self.cert_path,
                                   timeout=timeout)
            elif method == 'PATCH':
                r = session.patch(url, data=payload, headers=headers,
                                  auth=self.auth, verify=self.cert_path,
                                  timeout=timeout)
            else:
                sys.exit(127)
        except Timeout:
            print('Failure: failed to establish a new connection to the host,'
                  ' you are advised to set the timeout period to '
                  'a value greater than %d seconds.'
                  % default_timeout)
            sys.exit(127)
        except SSLError as ex:
            # Modify: 2021.3.10 Print error information.
            print(ex)
            sys.exit(127)
        except (AttributeError, SystemError, TypeError, ValueError, IOError):
            traceback.print_exc()
            raise common_function.CustomError('failed to establish'
                                              ' a new connection to the host')

        return self.dispose_result(files, r)

    def get_headers(self, headers):
        """
        功能描述：初始化https的headers，头部信息
        参数： headers (dict):可选参数，请求Header携带的数据
        返回值：None
        异常描述：None
        """
        if headers is None:
            if self.headerhost is not None:
                headers = {'X-Auth-Token': self.token,
                           'If-Match': self.etag,
                           'Host': self.headerhost}
            else:
                headers = {'If-Match': self.etag}
        return headers

    def get_url(self, resource):
        """
        功能描述：初始化url
        参数： resource (str): 请求的RESTful资源路径
        返回值：None
        异常描述：None
        """
        if self.port is not None:
            url = r'https://%s:%d%s' % (self.host, self.port, resource)
        else:
            url = r'https://%s%s' % (self.host, resource)
        return url

    def dispose_result(self, files, r):
        """
        Function Description:Processing the data returned by the
         Redfish interface.
        Parameter:files dict: file infomation
        r dict:result of the redfish interface
        Modify: 2020.3.20 If NoValidSession is returned when the upgradefw
        command is executed, re-establish a session and send the
        command again.
        Return Value: r object:the response object is returned
        """
        if r.status_code == 401:
            err_401_proc(r)
        elif r.status_code == 403:
            if files is not None:
                print('Failure: insufficient privilege '
                      'or server is doing another request')
            else:
                print('Failure: you do not have the required permissions to'
                      ' perform this operation')
            sys.exit(147)
        elif r.status_code == 500:
            print('Failure: the request failed due to an internal'
                  ' service error')
            sys.exit(244)
        elif r.status_code == 501:
            print('Failure: the server did not '
                  'support the functionality required')
            sys.exit(245)
        elif r.status_code == 409:
            error_info_check(r)
            sys.exit(153)
        elif r.status_code == 405:
            print('Failure: A request was made of a resource'
                  ' using a request method not supported by that resource.')
            sys.exit(149)
        elif r.status_code == REDFISH_STATUS_CODE_412:
            print("Failure: precondition failed")
            sys.exit(UREST_STATUS_CODE_156)
        elif r.status_code == common_function.BAD_GATEWAY_CODE:
            # Modify: 2021/10/28 Troubleshooting When the Inband Proxy Is
            # Configured
            print("Failure: failed to establish a new connection to the host")
            traceback.print_exc()
            sys.exit(common_function.UREST_STATUS_CODE_127)

        else:
            return r

    def get_resource(self, url, headers=None, timeout=10):
        """
        #=====================================================================
        #   @Method:  通过RESTful接口获取URL对应的信息。
        #   @Param:   url:
                      资源路径；headers:请求头信息，默认为空时由request接口拼接
                      timeout:查询操作默认超时时间；
        #   @Return:  dict：
                      成功，'status_code', 响应状态码200; 'resource', URL节点信息，
        #             失败，'status_code', 响应状态码; 'message', 错误提示信息。
        #   @author:
        #=====================================================================
        """
        resource_get = ['GET', url, timeout]
        r = self.retry_request(resource_get, headers)
        if r is None:
            return None

        if r.status_code == 200:
            ret = {'status_code': r.status_code,
                   'resource': json.loads(r.content.decode('utf8', 'ignore')),
                   'headers': r.headers}

            if 'ETag' in list(ret['headers'].keys()):
                self.etag = ret['headers']['ETag']
            elif 'etag' in list(ret['headers'].keys()):
                self.etag = ret['headers']['etag']
        else:
            try:
                ret = {'status_code': r.status_code,
                       'message': r.json(),
                       'headers': r.headers}
            except (AttributeError, ValueError):
                ret = {'status_code': r.status_code,
                       'message': r,
                       'headers': r.headers}
            if 'ETag' in list(ret['headers'].keys()):
                self.etag = ret['headers']['ETag']
            elif 'etag' in list(ret['headers'].keys()):
                self.etag = ret['headers']['etag']

        return ret

    def delete_resource(self, url, headers=None, timeout=10):
        """
        #=====================================================================
        #   @Method:  delete_resource
        #   @Return:
        #   @Date: 20170829
        #=====================================================================
        """
        resource_delete = ['DELETE', url, timeout]
        r = self.retry_request(resource_delete, headers)
        if r is None:
            return None

        if r.status_code == 200:
            ret = {'status_code': r.status_code,
                   'resource': json.loads(r.content.decode('utf8', 'ignore')),
                   'headers': r.headers}
        else:
            try:
                ret = {'status_code': r.status_code,
                       'message': r.json(),
                       'headers': r.headers}
            except (AttributeError, ValueError):
                ret = {'status_code': r.status_code,
                       'message': r,
                       'headers': r.headers}
        return ret

    def set_resource(self, url, payload, headers=None, timeout=10):
        """
        #=====================================================================
        #   @Method:  set_resource
        #   @Param:   url
        #   @Return:  dict
        #   @Date: 20170830
        #=====================================================================
        """
        resource_patch = ['PATCH', url, timeout]
        resp = self.retry_request(resource_patch, headers=headers, data=payload)
        if resp is None:
            return None
        if resp.status_code == 200:
            ret = {'status_code': resp.status_code,
                   'resource': json.loads(
                       resp.content.decode('utf8', 'ignore')),
                   'headers': resp.headers}
        else:
            try:
                ret = {'status_code': resp.status_code,
                       'message': resp.json(),
                       'headers': resp.headers}

            # set_resource exception
            except (AttributeError, ValueError):
                ret = {'status_code': resp.status_code,
                       'message': resp,
                       'headers': resp.headers}
        return ret

    def create_resource(self, url, payload=None, files=None, timeout=10):
        """
        #=====================================================================
        #   @Method:  create_resource
        #=====================================================================
        """
        headers = None
        resource_post = ['POST', url, timeout]
        r = self.retry_request(resource_post, headers=headers, data=payload,
                               files=files)
        if r is None:
            return None

        if r.status_code in [201, 200, 202]:
            if url == "/redfish/v1/UpdateService/FirmwareInventory":
                resource = r.content
            elif ("/Actions/Oem/%s/Manager.GeneralDownload" %
                  common_function.COMMON_KEY in url):
                resource = r.content
            else:
                resource = json.loads(r.content.decode('utf8', 'ignore'))
            ret = {'status_code': r.status_code,
                   'resource': resource,
                   'headers': r.headers}

        else:
            try:
                ret = {'status_code': r.status_code,
                       'message': r.json(),
                       'headers': r.headers}
            # create_resource exception
            except (AttributeError, ValueError):
                ret = {'status_code': r.status_code,
                       'message': r,
                       'headers': r.headers}
        return ret

    def get_managers_info(self, url="/redfish/v1/Managers/"):
        """
        #=====================================================================
        #   @Method:  通过RESTful接口获取Managers资源信息。
        #   @Param:   url:资源路径；
        #   @Return:  dict
        #   @author:
        #=====================================================================
        """
        return self.get_resource(url)

    def get_slotid(self):
        """
        Function Description:getting slot id
        Return Value: slotid str:server slot id
        Modify: 2018.12.12 Modify prompt information.
        """
        managers_info = self.get_managers_info()
        if managers_info is None:
            return None

        slotid = None
        if managers_info['status_code'] == 200:
            if 'resource' in managers_info and \
                    'Members' in managers_info['resource']:
                if isinstance(managers_info['resource']['Members'], list):
                    if '@odata.id' in managers_info['resource']['Members'][0]:
                        slotid = managers_info['resource']['Members'][0][
                            '@odata.id'].split(r'/')[4]
            else:
                print("The slotid is not found.")
        else:
            get_error_info(managers_info)
            set_exit_code(managers_info)
        return slotid

    def get_common_key(self):
        resp = self.get_resource(common_function.REDFISH_VERSION_URL)
        if resp and resp.get(common_function.STATUS_CODE_KEY)\
                == REDFISH_STATUS_CODE_200:
            common_function.init_common_key(resp, common_function.PRODUCT_KEY)
        else:
            raise CustomError(resp)

    # Add flag parameter,
    # when task is completed,return 'Completed' instead of exiting
    def print_task_prog(self, response=None, maxtime=10, flag=None):
        """
        Function Description:Displaysing the task progress
        Parameter:response dict: Resource information
         corresponding to the task
        maxtime int:default maximum running duration of a task
        flag str:subcommand
        Modify: 2019.1.17 Default timeout parameter normalization.
        """
        # Modify: 2019.9.18 Modified the code review comments
        success_status = 'Completed'
        failed_status = 'Exception'
        if response is None:
            return None
        taskid = response['resource']['@odata.id']
        task_state, task_resp = self.get_task_state(taskid)
        if task_state == failed_status:
            return failed_status

        if task_state == success_status:
            if flag in flag_state:
                return success_status
            print('Success: successfully completed request')
            sys.exit(0)

        step = float(100) / maxtime
        cur_perc = step

        # TaskPercentage有值，取TaskPercentage；TaskPercentage没值，按输入时间计算
        while task_state == 'Running':
            vendor_value = common_function.get_vendor_value(task_resp)
            task_percent = vendor_value['TaskPercentage']
            cur_perc = print_task_percent(cur_perc, step, task_percent)
            time.sleep(1)
            # Modify: 2020.3.20 upgradefw如果遇到NoValidSession，
            # 重新建立session，重新发送命令
            task_state, task_resp = self.get_task_state(taskid)
            if task_resp is None:
                return None

        sys.stdout.write('                                                \r')
        sys.stdout.flush()
        if task_state == failed_status:
            return failed_status

        if task_state == success_status:
            if flag in flag_state:
                return success_status
            sys.stdout.write('Success: successfully completed request\n')
            sys.stdout.flush()
            sys.exit(0)
        return None

    def get_task_state(self, taskid):
        """
        功能描述：urest 通过taskid获取，当前的状态
        参数： None
        返回值：None
        异常描述：None
        """
        task_state = None
        task_resp = self.get_resource(taskid, timeout=120)
        if task_resp is not None:
            if task_resp['status_code'] != 200:
                traceback.print_exc()
                print('Failure: failed to establish a '
                      'new connection to the host')
                set_exit_code(task_resp)
            else:
                task_state = task_resp['resource']['TaskState']
        return task_state, task_resp

    def create_inner_session(self):
        """
        Function Description:create inner session
        Return Value:bool
        """
        import getbmctoken
        try:
            self.token = getbmctoken.get_inner_session()
        except common_function.CustomError as error:
            print(error)
            sys.exit(common_function.UREST_STATUS_CODE_127)

    def delete_inner_session(self):
        """
        #======================================================================
        #   @Method:  删除带内Session
        #   @Param:
        #   @Return:
        #   @author:
        #======================================================================
        """
        self.token = None
        return True

    def set_inner_bmcinfo(self):
        """
        Function Description:set inner bmcinfo
        Return Value:bool
        """
        error_message = 'Failure: failed to establish a ' \
                        'new connection to the host'
        try:
            import getbmcinfo
        except ImportError:
            print(error_message)
            return False

        # devirtual_flag:True is cdev,False is veth
        devirtual_flag = getbmcinfo.get_devirtualization()
        if devirtual_flag or getbmcinfo.get_usb():
            try:
                self.host = "127.0.0.1"
                self.port = getbmcinfo.get_devirtual_port()
                self.headerhost = "127.0.0.1"
            except (ValueError, SystemError, Timeout):
                print(error_message)
                return False
            except CustomError as e:
                print(e)
                return False
        else:
            ibmcmode = 'IPv6'
            ibmcip = ''
            try:
                self.host = getbmcinfo.getinnerhost(ibmcmode, ibmcip)
                self.port = getbmcinfo.getinnerport()
                self.headerhost = getbmcinfo.getinnerheaderhost(ibmcmode,
                                                                ibmcip)
            except (BaseException, Timeout):
                print(error_message)
                return False
        return True

    def check_storages(self, systems, storage, str_args='-I'):
        """
        #=====================================================================
        #   @Method: 对存储资源预先检查
        #   @Param:
        #   @Return:
        #   @author:
        #=====================================================================
        """
        url = systems + "/Storages"
        resp = self.get_resource(url)
        if resp is None:
            return None

        if resp['status_code'] != 200:
            if resp['status_code'] == 404:
                print('Failure: resource was not found')
            get_error_info(resp)
        # 看控制器url是否存在是否为以前版本
        else:
            if resp['resource']['Members@odata.count'] == 0:
                print('Failure: resource was not found')
                return resp
            for i in range(0, len(resp['resource']['Members'])):
                flag = False
                url = resp['resource']['Members'][i]['@odata.id']
                if url.find("RAIDStorage") > 0:
                    flag = True
                    break
            if flag:
                url = systems + storage
                resp = self.get_resource(url)
                if resp is None:
                    return None

                if resp['status_code'] != 200:
                    if resp['status_code'] == 404:
                        str1 = "Failure: the value of "
                        error = str1 + str_args + " parameter is invalid"
                        print(error)
                        sys.exit(UREST_STATUS_CODE_2)
                    return resp
            else:
                print('Failure: resource was not found')
                sys.exit(148)
        return resp

    def set_auth(self):
        """
        #======================================================================
        #   @Method:  设置basic auth信息
        #   @Param:
        #   @Return:
        #   @author:
        #======================================================================
        """
        self.auth = requests.auth.HTTPBasicAuth(self.username, self.password)
        return True

    def get_os_firmware_or_driver(self, os_url):
        """
        Function Description:Obtaining Upgradeable Firmware/Driver Information
        Parameter:os_url str: url
        Modify: 2019.1.17 Default timeout parameter normalization.
        Return Value: resp_os_info dict:result of the redfish interface
        """
        resp_os_info = self.get_resource(os_url, timeout=30)

        if resp_os_info is None:
            return None
        if resp_os_info['status_code'] == 200:
            # 可升级固件/驱动信息
            common_key_info = common_function.get_vendor_value(resp_os_info)
            print(PRINT_FORMAT % ('Name', ':',
                                  resp_os_info['resource']['Name']))
            print(PRINT_FORMAT % ('BDF', ':',
                                  common_key_info['BDFNumber']['BDF']))
            print(PRINT_FORMAT % ('RootBDF', ':',
                                  common_key_info['BDFNumber']['RootBDF']))
            print(PRINT_FORMAT % ('Model', ':',
                                  common_key_info['Model']))
            print(PRINT_FORMAT % ('VendorID', ':',
                                  common_key_info['VendorID']))
            print(PRINT_FORMAT % ('DeviceID', ':',
                                  common_key_info['DeviceID']))
            print(PRINT_FORMAT % ('SubsystemVendorID', ':',
                                  common_key_info['SubsystemVendorID']))
            print(PRINT_FORMAT % ('SubsystemDeviceID', ':',
                                  common_key_info['SubsystemDeviceID']))
            print(PRINT_FORMAT % ('DeviceSilkScreen', ':',
                                  resp_os_info['resource'][
                                      'DeviceSilkScreen']))
            print(PRINT_FORMAT % ('DeviceLocation', ':',
                                  resp_os_info['resource']['DeviceLocation']))
            print('-' * 40)

        return resp_os_info
