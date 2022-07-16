# -*- coding: utf-8 -*-
"""
Function: common_function.py moudle. This moudle mainly involves the
Error Code or Common functions function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2018-2021
"""
import argparse
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from json import loads
import getpass

REDFISH_STATUS_CODE_200 = 200
REDFISH_STATUS_CODE_201 = 201
REDFISH_STATUS_CODE_400 = 400
REDFISH_STATUS_CODE_404 = 404
REDFISH_STATUS_CODE_409 = 409
REDFISH_STATUS_CODE_412 = 412
REDFISH_STATUS_CODE_501 = 501
REDFISH_STATUS_CODE_202 = 202
INVALID_SESSION_CODE = 401
UREST_INVALID_SESSION_CODE = 145
UREST_STATUS_CODE_144 = 144
UREST_STATUS_CODE_148 = 148
UREST_STATUS_CODE_127 = 127
UREST_STATUS_CODE_130 = 130
UREST_STATUS_CODE_0 = 0
UREST_STATUS_CODE_2 = 2
UREST_STATUS_CODE_156 = 156
TIMEOUT_THIRTY = 30
TIMEOUT_ONE_HUNDRED_TWENTY = 120
TIMEOUT_THREE_HUNDRED = 300
TIMEOUT_UPDATE = 1800
MAX_TIMEOUT = 3600
BAD_GATEWAY_CODE = 502
HTTPS_SUB_COMMAND = 'importremotehttpsservercert'
INPUT_INFO = "Input 'q' quit:"
HELP = 'use /tmp/filename for a local file ' \
       'and ip/directory/filename for a remote file. '
status_dic = {201: 0, 202: 0, 200: 0, 400: 144, 401: 145, 403: 147, 404: 148,
              405: 149, 409: 153, 500: 244, 501: 245,
              UREST_STATUS_CODE_127: UREST_STATUS_CODE_127,
              UREST_STATUS_CODE_2: UREST_STATUS_CODE_2}
subcommand_list = ["getdiaginfo", "getscreenshot"]
key_value = None
PROTOCOL_LIST = ['https', 'scp', 'sftp', 'cifs', 'nfs']
SUBCOMMAND_RL_SERVER_LIST = ["config", "exportcsr", "getdiaginfo",
                             "import2factorcert", "importldapcert",
                             "importntpkey", "importsslcert",
                             "importsyslogcert", "importsshpubkey",
                             "upgradefw", HTTPS_SUB_COMMAND]
password = None
access_user = None
REQUIRED_FLAG = "required_flag"
HELP_INFO = "help_info"
LOCAL = "local"
REMOTE = "remote"
PROTOCOL = 'protocol'
CODE = "Code"
RESULT = "Result"
ERROR = "Error"

REGULAR_MODE_LINE = r"ibmcmode[\s]+=[\s]+[\S]*"
REGULAR_MODE_KEY = r"ibmcmode[\s]+=[\s]+"
REGULAR_IP_LINE = r"ibmcip[\s]+=[\s]+[\S]*"
REGULAR_IP_KEY = r"ibmcip[\s]+=[\s]+"

ERROR_MESSAGE = 'no data available for the resource'

custom_stdin = None
BMA_ERROR_KEY = 'message'
BMC_BMA_ERROR_KEY = 'Message'
IPV4 = "IPv4"
IPV6 = "IPv6"
PRODUCT_NAME_KEY = "ProductName"
OEM_KEY = "Oem"
RESOURCE_KEY = "resource"
COMMON_KEY = "Huawei"
BMA_PATH = "/opt/huawei/ibma/" if os.path.exists(
    "/opt/huawei/ibma/") else "/opt/ibma/"
BMA_BIN_PATH = ("/opt/huawei/ibma/bin/"
                if os.path.exists("/opt/huawei/ibma/bin/")
                else "/opt/ibma/bin/")
STATUS_CODE_KEY = 'status_code'
PRODUCT_KEY = "ProductName"
REDFISH_VERSION_URL = "/redfish/v1"
INTERNAL_ERROR_MESSAGE = 'internal command error.'
SLOT_ID_ERROR = "failed to obtain the system resource ID."
RESOURCE_NULL = "failed to obtain the resources."
KEYERROR_FORMATTER = 'Failure: %s attribute {} cannot' \
                     ' be found.' % (INTERNAL_ERROR_MESSAGE)
USB_DEVICE = "USB"
USB_DEV_FILE = ("/dev/lcd2" if os.path.exists("/dev/lcd2") else "/dev/lcd0")
PCIE_DEVICE = "PCIe"
NOWIN_PCIE_DEV_FILE = "/dev/hwibmc2"
SERVICE_TYPE_FILE = {USB_DEVICE: USB_DEV_FILE, PCIE_DEVICE: NOWIN_PCIE_DEV_FILE}

CDEV_DEVICE = "Cdev"
BOB_CHANNEL_TYPE = "%s-Linux" % USB_DEVICE
CHANNEL_TYPE_KEY = "ChannelType"
CDEV_CHANNEL_ENABLED_KEY = "CdevChannelEnabled"

# Character device exception prompt
DEVICE_ERROR_MESSAGE = "Failure: the character device is" \
                       " abnormal. try again later."
# Message indicating that the character device does not exist
CDEVICE_NOT_EXIT_MESSAGE = "Failure: No character device is available." \
                           " Install the BMA" \
                           " to enable the communication between" \
                           " the uREST and iBMC," \
                           " or enable the USB character device channel" \
                           " for communication between the uREST and iBMC."
NOLINUX_CDEVICE_NOT_EXIT_MESSAGE = "Failure: No character device is" \
                                    " available. Install the BMA."
# Number of bytes read from CDEV character device file
PCIE_BYTES_NUMBER = 255
# os type
PLATFORM_TYPE = "linux"

# Modify: 2021.08.28 Privacy Deserving Regular Expression
P_PRIVACY_VALUE = r".*value(.*)for the property {}.*"
# Modify: 2021.08.28 Failure Prompt Keyword
ERROR_KEY = "Failure: "
# Modify: 2021.08.28 Failure message output style
EXCEPTION_FORMAT = "{:>%s}"
# Modify: 2021.08.28 set user 200 exit code
UREST_REQUEST_ERROR = 144
# Modify: 2021.08.28 Header message indicating partial failure
EXCEPTION_PROMPT = '{}some of the settings failed.' \
                   ' possible causes include the following: '.format(ERROR_KEY)

USERS_INFO_NULL = "the server does not contain information about" \
                  " user collection resource."
USER_NOT_EXITS = "the user does not exist."
PRO_FORMAT = '%-30s: %s'
CERT_NOT_EXIT_MESSAGE = "the required certificates do not exist." \
                        " Obtain and store {} and {}." \
                        " For details, see section 3.2 in" \
                        " FusionServer Tools 2.x.x uREST User Guide. "
DEPTH_PYTHON = 2000
# retry_count
RETRY_COUNT = 10
# Timeout interval for reading file from USB character device
READ_CHARACTER_DEVICE_TIMEOUT = 5
# Interval time
INTERVAL_TIME = 1
# manufacturer vendor IPMI ID
VENDOR_IPMI_ID = ["0x14", "0xe3", "0x00"]


class CustomError(Exception):
    """
    Class Description:Custom Error
    """

    def __init__(self, error_info=INTERNAL_ERROR_MESSAGE,
                 code=UREST_STATUS_CODE_127):
        self.error_info = error_info
        self.code = code

    def get_dict(self):
        """
        Function Description:Convert the error information to
         the error information in the specified dictionary format.
        Return Value: error_message dict
        """
        if not isinstance(self.error_info, dict):
            error_dict = {"status_code": self.code, "message": {"error": {
                "@Message.ExtendedInfo": [{"Message": self.error_info}]}}}
            return error_dict
        else:
            return self.error_info

    def __str__(self):
        return self.error_info


class UniqueStore(argparse.Action):
    """
    Function Description:Restriction Parameter
    """

    def __call__(self, parser, namespace, values, option_string):
        if getattr(namespace, self.dest, self.default) is not self.default:
            parser.error(option_string + " appears several times.")
        setattr(namespace, self.dest, values)


def stringtobool(strs):
    """
    Function Description:‘False’ to False， ‘True’ to True
    Parameter:strs (string):‘False’ or True
    """
    if strs == 'False':
        return False
    return True


def set_exit_code(resp):
    """
    exit code
    :param resp:
    :return:
    """
    if not resp:
        sys.exit(UREST_STATUS_CODE_127)

    if resp.get('status_code') is not None:
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
    except (KeyError, IndexError, TypeError):
        print('Failure: status code ' + str(ret['status_code']))


def payload_file(json_file, file_des=""):
    """
    Function Description:json file to json object
    Parameter:json_file str:JSON file path
    Return Value:json_obj object:Python object
    """
    if not os.path.isfile(json_file):
        raise CustomError("Failure: The %s file in JSON"
                          " format does not exist." % file_des)

    try:
        with open(json_file, mode='r', encoding='utf-8') as file_obj:
            file_content = file_obj.read()
    except BaseException:
        raise CustomError("Failure: Failed to open the %s file"
                          " in JSON format." % file_des)

    if "{" not in file_content:
        raise CustomError('Failure: Failed to parse the %s file'
                          ' in JSON format.' % file_des)

    try:
        json_obj = loads(file_content)
    except BaseException:
        raise CustomError('Failure: Failed to parse the'
                          ' %s file in JSON format.' % file_des)

    return json_obj


def set_file_path(filepath):
    """
    Process the file name.
    :param filepath:local file path
    :return:BMC file path
    """
    file_dir = os.path.dirname(filepath)
    if not os.path.exists(file_dir):
        print("Failure: The file path does not exist.")
        return None
    filename = filepath[len(file_dir) + 1:]
    now = time.time()
    local_time = time.localtime(now)
    file_path = "/tmp/" + time.strftime('%Y%m%d%H%M%S',
                                        local_time) + "_" + filename
    return file_path


def export_local_path(client, slotid, file_path, args):
    """
    Download file to local path.
    :param client: RedfishClient object
    :param slotid: slot id
    :param file_path:local file path
    :return:
    """
    url = "/redfish/v1/Managers/%s/Actions/Oem/" \
          "%s/Manager.GeneralDownload" % (slotid, COMMON_KEY)
    payload = {"TransferProtocol": "HTTPS", "Path": file_path}
    resp = client.create_resource(url, payload)
    if resp.get("status_code", None) == 200:
        # Modify:2019.12.21 Modify issue getdiaginfo interface
        # failed when exporting to local
        if args.subcommand in subcommand_list:
            message = resp.get("resource", None)
        else:
            message = str(resp.get("resource", None), encoding='utf-8')
        if message is not None:
            if not creat_res_file(args.file, message, args):
                sys.exit(2)
    else:
        get_error_info(resp)
        set_exit_code(resp)


def init_common_key(resp, search_key):
    """
    Function Description:Obtains the key value in the dictionary.
    Parameter:resp dict:redfish Result Value
    """
    try:
        global COMMON_KEY
        redfish_dict = resp[RESOURCE_KEY][OEM_KEY]
        for key in redfish_dict:
            if search_key in redfish_dict.get(key):
                COMMON_KEY = key
                break
    except (KeyError, TypeError):
        pass


def get_vendor_value(resp):
    """
    Function Description:get vendor value
    Parameter:resp dict:redfish value
    Return: Request content
    """
    try:
        return resp[RESOURCE_KEY][OEM_KEY][COMMON_KEY]
    except KeyError:
        raise CustomError(KEYERROR_FORMATTER.format("%s or %s or"
                                                    " %s" % (RESOURCE_KEY,
                                                             OEM_KEY,
                                                             COMMON_KEY)))


def creat_res_file(file_path, message, args):
    """
    export JSON files
    :param file_path: local file path
    :param message: document content
    :param args: parameters
    :return: False or True
    """
    prompt_info = "Failure: insufficient permission for the file or " \
                  "file name not specified, perform this " \
                  "operation as system administrator/root, " \
                  "or specify a file name"
    # Check the path.
    file_dir = os.path.dirname(file_path)
    if not os.path.exists(file_dir):
        print("Failure: The file exports path does not exist.")
        return False

    if os.path.isdir(file_path):
        print("Failure: Please specify an export file name.")
        return False
    try:
        if args.subcommand in subcommand_list:
            write_file(file_path=file_path, file_content=message,
                       text_flag=False)
        else:
            write_file(file_path=file_path, file_content=message)
    except OSError:
        print(prompt_info)
        sys.exit(2)

    return True


def local_or_remote_file_path(file_dict, client):
    """
    Function Description:Obtain the file path on the remote server or BMC path.
    Parameter:file_dict dict: file path in the command line
    client refishClient: class object
    """
    if file_dict.get(LOCAL):
        file_path = import_file_path(client, file_dict.get(LOCAL))
        if not file_path:
            sys.exit(UREST_STATUS_CODE_2)

    else:
        file_path = file_dict.get(REMOTE)

    return file_path


def import_file_path(client, filepath):
    """
    Import with local path.
    :param client: RedfishClient object
    :param filepath: local file path
    :return: BMC file path
    """
    file_dir = os.path.dirname(filepath)
    if not os.path.exists(file_dir):
        print("Failure: The file imports path does not exist.")
        return None
    filename = filepath[len(file_dir) + 1:]
    ret = upload_file(client, filepath, filename)
    if ret is False:
        return None
    file_path = '/tmp/web/' + filename
    return file_path


def upload_file(client, filepath, filesname):
    """
    Function Description:upload file
    Parameter:client refishClient:class object
    filepath str: file path
    filesname str: file name
    Modify: 2020.06.18 error information is transparently
     transmitted when the importsslcert command is run.
    """
    url_upload = "/redfish/v1/UpdateService/FirmwareInventory"
    if not os.path.isfile(filepath):
        print("Failure: the file does not exist")
        return False
    with open(filepath, 'rb') as file_obj:
        files = {'imgfile': (filesname, file_obj, "multipart/form-data",
                             {'user_name': client.username})}
        if files is None:
            print("Failure: the file open failed, please try again")
            return False
        resp = client.create_resource(url_upload, files=files, timeout=300)
    if resp is None:
        return False
    try:
        if resp['status_code'] != 202:
            message_info = ""
            messages = resp['message']['error']['@Message.ExtendedInfo']
            if messages:
                message_dict = messages[0]
                message_info = message_dict.get('Message', "")
            print('Failure: Upload files failed.%s' % message_info)
            set_exit_code(resp)
    except (KeyError, AttributeError, TypeError):
        print('Failure: Upload file failed.')
        sys.exit(UREST_STATUS_CODE_127)
    return True


def print_status_code(resp):
    """
    print status code
    :return:
    """
    error_code = "0"
    if resp['status_code']:
        error_code = str(resp['status_code'])
    print('Failure: status code ' + error_code)


def change_message(messageinfo):
    """
    changemessage Change strings with capitalized first letters
    and ended with '.' into strings with lowercase first letters and delete '.'.
    :param messageinfo:
    :return:
    """
    if (messageinfo[0] >= 'A' and messageinfo[0] <= 'Z') \
            and (messageinfo[-1] == '.'):
        return messageinfo[0].lower() + messageinfo[1:-1]
    return messageinfo


def get_cd_info(client, slotid):
    """
    get cd information
    :param self:
    :param client:
    :param slotid:
    :return:
    """

    url_cd = "/redfish/v1/Managers/%s/VirtualMedia" % slotid
    resp = client.get_resource(url_cd)
    url = ""
    if resp is None:
        return url, None
    if resp['status_code'] == 200:
        vmm = resp["resource"].get("Members", "")
        # Query vmm information, if there is no resource, just like 404
        vmm_len = len(vmm)
        if vmm_len == 0:
            print('Failure: resource was not found')
            return url, resp
        idx = 0
        while idx < vmm_len:
            cd_info = vmm[idx]["@odata.id"].split("/")
            if cd_info[-1] == "1" or cd_info[-1] == "CD":
                url = vmm[idx]["@odata.id"]
                break
            idx += 1
        # Url is "", there is no VMM resource information
        if url == "":
            print('Failure: resource was not found')
            return url, resp
    elif resp['status_code'] == 404:
        print('Failure: resource was not found')
        return url, resp
    return url, resp


def all_none(*fun_param):
    """
    Function Description:all parameters are None.
    Parameter:fun_param tuple: CLI command's Parameter
    """
    for parameter in fun_param:
        if parameter is not None:
            return False
    return True


def has_none(*fun_param):
    """
    Function Description:one parameter is None.
    Parameter:fun_param tuple: CLI command's Parameter
    """
    for parameter in fun_param:
        if parameter is None:
            return True
    return False


def check_real_path_parameter(parser, args):
    """
    Function Description:check path
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    args_dict = vars(args)
    imageuri_value = args_dict.get('imageuri')
    file_value = args_dict.get('file')
    signatureuri_value = args_dict.get('signatureuri')
    protocol_value = args_dict.get(PROTOCOL)
    accessuser_value = args_dict.get('accessuser')

    if file_value is not None:
        if protocol_value or accessuser_value:
            parser.error("-PRO or -U(ACCESSUSER) is redundant.")

    if imageuri_value is not None and file_value is not None:
        parser.error("specify at most one of -i or -F.")

    if imageuri_value is None and file_value is None:
        parser.error("specify at least one of -i and -F.")

    if imageuri_value or signatureuri_value:
        if protocol_value is None and accessuser_value:
            parser.error("-PRO is required.")


def unpack_remote_server_path(sub_parser, args_image, args_pro,
                              args_acc, args_signature=None):
    """
    Function Description:unpack remote server path
    Parameter:sub_parser (ArgumentParser):subcommand ArgumentParser
    image_uri (dict): help and required's info
    Modify: 2021.3.8 The help information of -U is optimized.
    """
    if args_image:
        sub_parser.add_argument('-i', dest='imageuri',
                                required=args_image.get(REQUIRED_FLAG,
                                                        False),
                                help=args_image.get(HELP_INFO, HELP))
    if args_pro:
        sub_parser.add_argument('-PRO', dest=PROTOCOL,
                                required=args_pro.get(REQUIRED_FLAG, False),
                                choices=args_pro.get("protocol",
                                                     PROTOCOL_LIST),
                                help='file transfer protocol')

    if args_acc:
        sub_parser.add_argument('-U', dest='accessuser',
                                required=args_acc.get(REQUIRED_FLAG,
                                                      False),
                                help='user name of the remote file server')
        sub_parser.add_argument('-UP', dest='accesspassword',
                                required=args_acc.get(REQUIRED_FLAG,
                                                      False),
                                help='user password of the remote file server')

    if args_signature:
        sub_parser.add_argument('-si', dest='signatureuri',
                                required=args_signature.get(REQUIRED_FLAG,
                                                            False),
                                help=args_signature.get(HELP_INFO, HELP))


def splice_remote_server_path(args, remote_file_path=None):
    """
    Function Description:splice remote server path
    Parameter:args object:CLI command
    Return Value:file path on the file server.
    """

    if remote_file_path is None and args.imageuri:
        remote_file_path = args.imageuri

    if not args.protocol:
        return remote_file_path

    global password
    global access_user

    if args.accessuser is not None and password is None:
        access_user = args.accessuser
        password = args.accesspassword

    if not password and not access_user:
        name_pass = ""
    else:
        name_pass = "%s:%s@" % (access_user, password)

    return "%s://%s%s" % (args.protocol, name_pass, remote_file_path)


def replace_password(message, args_password):
    """
    Function Description:replace password
    Parameter:message str:error information
    args_password str:password
    Return Value:message str:result returned by redfish
    """
    if (args_password
            and message
            and isinstance(message, str)
            and args_password in message):
        return str(message).replace(args_password, "******")
    return message


def get_cmd_value(command=None, work_dir=None):
    """
    Function Description:Run the cmd command and return the result.
    Parameter:command str:command
    work_dir str: command working directory
    Return Value:result dict:the command execution result is returned.
    """
    try:
        global custom_stdin
        custom_stdin = subprocess.PIPE
        cmds = command.split("|")
        before_process_list = []
        code = -1
        result = ""
        error = ""
        for index, command_str in enumerate(cmds):
            args = shlex.split(command_str.strip())
            try:
                cmd_process = subprocess.Popen(args,
                                               stdin=custom_stdin,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE,
                                               shell=False,
                                               encoding="utf-8",
                                               cwd=work_dir)

                custom_stdin = cmd_process.stdout
            except subprocess.SubprocessError as e:
                raise CustomError(str(e))

            if index < len(cmds) - 1:
                before_process_list.append(cmd_process)
            else:
                # Allow p1 to receive a SIGPIPE if p2 exits.
                for before_process in reversed(before_process_list):
                    before_process.stdout.close()
                result, error = cmd_process.communicate()
                code = cmd_process.returncode
        return {RESULT: str(result).strip(), ERROR: str(error).strip(),
                CODE: code}
    except (SyntaxError, SystemError, TypeError, ValueError, OSError,
            AttributeError) as e:
        raise CustomError(str(e))


def is_success(result):
    """
    Function Description:check whether the command is executed successfully.
    Parameter:result dict:command execution result
    Return Value:bool
    """
    code = result.get(CODE)
    if code == 0:
        return True
    return False


def write_file(**kwargs):
    """
    Function Description:write file
    Parameter:result dict:command execution result
    text_flag bool:binary mode
    flags int:Variables with simple values
    modes int:Permission
    flag bool:Write Text(True)
    """
    file_path = kwargs.get("file_path")
    file_content = kwargs.get("file_content")
    text_flag = kwargs.get("text_flag", True)
    open_flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
    flags = kwargs.get("flags", open_flags)
    open_mode = stat.S_IWUSR | stat.S_IRUSR
    mode = kwargs.get("mode", open_mode)

    if text_flag:
        with os.fdopen(os.open(os.path.realpath(file_path), flags, mode),
                       mode='w+',
                       encoding='utf-8') as file_out:
            file_out.write(file_content)
            file_out.flush()

    else:
        with os.fdopen(os.open(os.path.realpath(file_path), flags, mode),
                       mode='wb') as file_out:
            file_out.write(file_content)
            file_out.flush()


def get_channel_info(client):
    """
    Function Description:print information
    Parameter:resp dict:redfish result
    """
    slotid = client.get_slotid()
    if slotid is None:
        raise CustomError(INTERNAL_ERROR_MESSAGE)

    url = "/redfish/v1/Managers/%s/SmsService" % slotid
    resp = client.get_resource(url)
    if not resp:
        raise CustomError(INTERNAL_ERROR_MESSAGE)

    if resp['status_code'] != 200:
        raise CustomError(resp)

    resp_resource = resp.get(RESOURCE_KEY)
    channel_type = resp_resource.get(CHANNEL_TYPE_KEY)
    channel_status = resp_resource.get(CDEV_CHANNEL_ENABLED_KEY)
    if channel_type is None and channel_status is None:
        raise CustomError('attributes %s and %s are not the resource'
                          ' attributes.' % (CHANNEL_TYPE_KEY,
                                            CDEV_CHANNEL_ENABLED_KEY))

    return channel_type, channel_status, resp


def print_error_message(resp, p_attributes=None, key=None):
    """
    Function Description:the patch request is not in the 200 state,
                         print error message
    Parameter: resp dict: redfish value
               p_attributes tuple: Privacy Attribute Names
               key str: fields to be deleted
    Modify: 2021.08.28 If the Redfish return code is not 200,
                       multiple failure messages are displayed.
    """
    if not resp or resp.get(STATUS_CODE_KEY) == REDFISH_STATUS_CODE_200:
        return

    try:
        messages = resp['message']['error']['@Message.ExtendedInfo']

        for index, message_dict in enumerate(messages):
            if not message_dict:
                continue

            set_privacy_property_value(message_dict, p_attributes)
            set_personalization_message(message_dict, key)
            error_index = index + 1
            if error_index == 1:
                print("%sthe reasons are as follows:" % ERROR_KEY)

            p_message = "{0}: {1}".format(error_index,
                                          message_dict.get(BMC_BMA_ERROR_KEY))
            exception_format = EXCEPTION_FORMAT % len("%s%s" % (ERROR_KEY,
                                                                p_message))
            print(exception_format.format(p_message))
    except (TypeError, KeyError, IndexError):
        print('Failure: status code %s' % str(resp.get('status_code')))


def set_personalization_message(message_dict, key=None):
    """
    Function Description:delete set personalization message
    Parameter: message_dict dict:redfish value
               key str: dehumanizing keyword and key is not zero
    """
    if not key or not message_dict:
        return

    message = message_dict.get(BMC_BMA_ERROR_KEY)
    if not message:
        return

    message_dict[BMC_BMA_ERROR_KEY] = (message.replace(key, "")
                                       if key in message else message)


def set_privacy_property_value(message_dict, p_attributes=None):
    """
    Function Description:set privacy property value
    Parameter: resp dict:redfish value
               p_attributes tuple: Privacy Attribute Names
    """
    if not p_attributes or not message_dict:
        return

    message = message_dict.get(BMC_BMA_ERROR_KEY)
    message_args = message_dict.get("MessageArgs")

    if not message or not message_args:
        return

    for p_attribute in p_attributes:
        if p_attribute not in message_args:
            continue

        privacy_values = re.findall(P_PRIVACY_VALUE.format(p_attribute),
                                    message)
        message = (message.replace(privacy_values[0], " ")
                   if privacy_values else message)

    message_dict[BMC_BMA_ERROR_KEY] = message


def print_result(resp, p_attributes=None, key=None,
                 success_message='Success: successfully completed request'):
    """
    Function Description:200 print result
    Parameter: resp dict: redfish value
               p_attributes tuple: Privacy Attribute Names
               key str: fields to be deleted
    Modify: 2021.08.28 If the Redfish return code is 200,
                       print information.
    """

    if not resp or resp.get(STATUS_CODE_KEY) != REDFISH_STATUS_CODE_200:
        return

    count_error = 0
    try:
        messages = resp['resource'].get('@Message.ExtendedInfo')

        if not messages:
            print(success_message)
            return

        for index, message_dict in enumerate(messages):
            if not message_dict \
                    or "success" in message_dict.get("MessageId").lower():
                continue

            count_error = error_index = index + 1
            if error_index == 1:
                print(EXCEPTION_PROMPT)

            set_privacy_property_value(message_dict, p_attributes)
            set_personalization_message(message_dict, key)

            p_message = "{0}: {1}".format(error_index,
                                          message_dict.get(BMC_BMA_ERROR_KEY))
            exception_format = EXCEPTION_FORMAT % (len("%s%s" % (ERROR_KEY,
                                                                 p_message)))
            print(exception_format.format(p_message))

        if not count_error:
            print(success_message)
        else:
            sys.exit(UREST_REQUEST_ERROR)

    except (TypeError, KeyError, IndexError) as e:
        raise CustomError(str(e))


def format_byte_to_hex_stream(byte_list):
    """
    Function Description：chang ASCII to command
            "1,2,3,4,5,6" -> "\x01\x02\x03\x04\x05\x06"
    Return Value:command str
    """
    hex_string = ''.join(
        ('{0:02x}'.format(int(c_byte, 16)) for c_byte in byte_list)).strip()
    # 需要先转换成 codecs 的bytes类型
    return bytes.fromhex(hex_string)


def display_error_message(client, resp):
    """
    #=====================================================================
    #   @Method:  print error message
    #   @Param:
    #   @Return:
    #   @author:
    #   @date:   2017-8-29 09:15:14
    #=====================================================================
    """
    messages = resp['message']['error']['@Message.ExtendedInfo']
    if messages is None or len(messages) == 0:
        return None

    message = messages[0]
    print(message)
    failure = change_message(message['Message'])
    resolution = message['Resolution']
    print('Failure: %s; Resolution: %s.' % (failure, resolution))


def get_protocol_type(imageuri):
    """
    Function Description:Obtains the protocol type.
    Parameter:imageuri str: File path on the remote file server
    """
    protocol_list = ['https', 'scp', 'sftp', 'cifs', 'nfs']
    for item in protocol_list:
        if imageuri.startswith(item):
            protocol = item.upper()
            return protocol


def format_uri(uri):
    """
    Function Description:Removing leading and trailing whitespace.
    Parameter:uri: local file path or file path on the remote file server
    """
    return uri.strip()
