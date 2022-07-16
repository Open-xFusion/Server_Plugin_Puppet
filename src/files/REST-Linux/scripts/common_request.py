# -*- coding:utf-8 -*-
"""
Function: common_request.py moudle. This moudle mainly involves the providing
 a universal interface function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2018-2021
"""
import json
from json import dumps
from os import path
import re
import sys
from scripts import common_function


status_dic = {400: 144, 401: 145, 403: 147, 404: 148,
              405: 149, 409: 153, 500: 244, 501: 245}
file_extension = ["gz", "jpeg"]
upload_fileurl = "/redfish/v1/UpdateService/FirmwareInventory"
file_download_url = None


def commonrequest_init(parser, parser_dict):
    """
    Function Description:initializing the Command for
    universal interface.
    Parameter:parser object: action object
    parser_dict dict: dictionary format of subcommand and ArgumentParser
    Modify: 2019.4.28 The help information is optimized.
    Return Value: subcommand
    """
    sub_parser = parser.add_parser('request',
                                   help='''common interface request''')
    sub_parser.add_argument('-I', dest='url',
                            required=True,
                            help='''request URL, starting with /redfish/''')
    sub_parser.add_argument('-T', dest='type',
                            required=True,
                            help='''request type''',
                            choices=['GET', 'POST', 'PATCH', 'DELETE'])
    sub_parser.add_argument('-B', dest='requestbodyfile',
                            required=False,
                            help='local file used to save the request body in '
                                 'JSON format or path of the file '
                                 'to be uploaded')
    sub_parser.add_argument('-F', dest='file',
                            required=False,
                            help='''local file used to export the result''')

    parser_dict['request'] = sub_parser

    return 'request'


def error_message_check(args, resp, flag=None):
    """
    #=====================================================================
    #   @Method:  print error message
    #   @Param:  args, parameter list
    #   @param:  resp, Returned structure
    #   @Return:
    #   @author:
    #   @date:
    #=====================================================================
    """
    result = True
    if resp['status_code'] not in [200, 201, 202]:
        info = resp["message"]
        print_result(args, info, flag=False)
        return False, info

    info = get_info(resp, args)
    if flag is False and file_download_url in args.url:
        return result, info

    if '@Message.ExtendedInfo' in info:
        print_result(args, info, flag=False)
        if args.file and args.file.split('.')[-1] not in file_extension:
            print("Failure: View %s to obtain"
                  " the failure details." % args.file)
        sys.exit(144)
    if flag:
        return result

    return result, info


def upload_file_check(client, args):
    """
    Upload files.
    :param client:
    :param args: parameter list
    :return:
    """
    payload = None
    file_obj = None
    resp = None
    if str(args.requestbodyfile).split('/')[-1] == args.requestbodyfile:
        filename = str(args.requestbodyfile).split("\\")[-1]
    else:
        filename = str(args.requestbodyfile).split('/')[-1]
    try:
        with open(args.requestbodyfile, 'rb') as file_obj:
            files = {'imgfile': (filename, file_obj, "multipart/form-data")}
            timeout = common_function.TIMEOUT_UPDATE
            resp = client.create_resource(args.url, payload, files=files,
                                          timeout=timeout)
    except IOError:
        print("Failure: Failed to open the uploaded file. "
              "Please try again.")
        sys.exit(common_function.UREST_STATUS_CODE_2)
    finally:
        if file_obj:
            file_obj.close()
    return resp


def request_patch_resource(client, args):
    """
    Function Description:PATCH request
    Parameter:client refishClient: class object
    args object:CLI command
    Modify: 2019.1.17 Default timeout parameter normalization.
    Return Value: resp dict:result of the redfish interface
    """
    get_resp = client.get_resource(args.url)
    if get_resp is None:
        sys.exit(127)

    result_flag = error_message_check(args, get_resp, flag=True)
    if not result_flag:
        status_code = status_dic.get(get_resp['status_code'])
        sys.exit(status_code)
    try:
        file_json_object = common_function.payload_file(args.requestbodyfile,
                                                        file_des='request body')
    except common_function.CustomError as e:
        print(e)
        sys.exit(common_function.UREST_STATUS_CODE_2)

    timeout = common_function.TIMEOUT_ONE_HUNDRED_TWENTY
    resp = client.set_resource(args.url,
                               file_json_object,
                               timeout=timeout)
    return resp


def request_post_resource(client, args):
    """
    POST request
    :param parser:
    :param client: RedfishClient object
    :param args: parameter list
    :return:
    """
    files = None
    if args.url == upload_fileurl:
        resp = upload_file_check(client, args)
    else:
        try:
            file_json_object = common_function.payload_file(
                args.requestbodyfile, file_des='request body')
        except common_function.CustomError as e:
            print(e)
            sys.exit(common_function.UREST_STATUS_CODE_2)

        timeout = common_function.TIMEOUT_THREE_HUNDRED
        resp = client.create_resource(args.url,
                                      file_json_object,
                                      files=files,
                                      timeout=timeout)
    return resp


def print_result(args, result_info, flag=None):
    """
    Import result
    :param parser:
    :param result_info:
    :param args:
    :return:
    """
    if args.file is not None:
        if flag is False and args.file.split('.')[-1] in file_extension:
            print(json.dumps(result_info, indent=4))
        else:
            creat_res_file(args, result_info, flag)
    else:
        print(json.dumps(result_info, indent=4))


def get_info(resp, args):
    """
    get info
    :param resp:
    :param args:
    :return:
    """
    if args.type != "POST":
        if resp['status_code'] != 200:
            info = resp["message"]
        else:
            info = resp["resource"]
    else:
        upload_file_url = "/redfish/v1/UpdateService/FirmwareInventory"
        if args.url == upload_file_url:
            resp['resource'] = json.loads(resp['resource'].decode('utf8',
                                                                  'ignore'))
        info = resp["resource"]

    return info


def check_parameter(parser, args):
    """
    Function Description:check CLI command
    Parameter:args object:CLI command
    parser object:subcommand ArgumentParser object
    """
    if not re.match(r'^/redfish.*$', args.url):
        parser.error("The URL format is incorrect. "
                     "The URL must start with /redfish/."
                     " Please enter the correct URL.")

    if args.requestbodyfile is None:
        if args.type == "POST" or args.type == "PATCH":
            parser.error("Argument -B is required.")

    elif args.type == "POST" and args.url == upload_fileurl:
        suffix = str(args.requestbodyfile).split('.')[-1]
        suffix_tuple = ("hpm", "zip", "asc", "cer", "pem", "cert",
                        "crt", "pfx", "p12", "xml", "keys", "pub", "crl")
        if suffix not in suffix_tuple:
            hints = [".%s" % n_suffix for n_suffix in suffix_tuple]
            parser.error('Failure: The format of the uploaded file is incorrect'
                         '.The file extension is optional'
                         ' (%s)' % ", ".join(hints))

    if args.file:
        # Check the path.
        file_dir = path.dirname(args.file)
        if not path.exists(file_dir):
            parser.error("Failure: The file exports path does not exist.")
        if path.isdir(args.file):
            parser.error("Failure: Please specify an export file name.")


def commonrequest(client, args):
    """
    Function Description:universal interface.
    Parameter:client refishClient: class object
    args object:CLI command
    Modify: 2019.1.17 Default timeout parameter normalization.
            2019.6.21 Print the prompt information.
    """
    global file_download_url
    file_download_url = "Actions/Oem/%s/Manager.GeneralDown" \
                        "load" % common_function.COMMON_KEY
    post_uri, resp = get_resp_posturi(args, client)
    result_flag, info = error_message_check(args, resp, flag=False)
    if result_flag:
        if post_uri:
            print("Location: " + post_uri)
        print_result(args, info, flag=True)

        if args.file is not None:
            print('Success: The request has been successfully completed.')
        sys.exit(0)
    else:
        if args.file is not None \
                and args.file.split('.')[-1] not in file_extension:
            print("Failure: View " + args.file +
                  " to obtain the failure details.")
        status_code = status_dic.get(resp['status_code'])
        sys.exit(status_code)


def get_resp_posturi(args, client):
    """
    功能描述:通过url获取redfish接口信息
    参数：args (list): parameter list
    client (RedfishClient):
    parser (ArgumentParser): subcommand argument parser
    返回值：file_path (str), 文件路径
    修改：None
    """
    post_uri = ""
    resp = None
    if args.type == "GET":
        resp = client.get_resource(args.url, headers=None,
                                   timeout=common_function.TIMEOUT_THIRTY)
    elif args.type == "DELETE":
        resp = client.delete_resource(args.url)
    elif args.type == "PATCH":
        resp = request_patch_resource(client, args)
    elif args.type == "DELETE":
        resp = client.delete_resource(args.url)
    elif args.type == "POST":
        resp = request_post_resource(client, args)
        if resp['status_code'] == 201:
            post_uri = resp['headers']['Location']
    if resp is None:
        sys.exit(127)
    return post_uri, resp


def creat_res_file(args, resource_dict, flag):
    """
    #=====================================================================
    #   @Method:  export JSON files
    #   @Param:   file_path, local file path
    #             resource_dict, request result
    #   @Return:
    #   @author:
    #=====================================================================
    """
    fail_info = "Failure: insufficient permission for the file " \
                "or file name not specified, perform this operation as " \
                "system administrator/root, or specify a file name"
    try:
        if flag is True and args.file.split('.')[-1] in file_extension \
                and file_download_url in args.url:
            common_function.write_file(file_path=args.file,
                                       file_content=resource_dict,
                                       text_flag=False)
        else:
            json_obj = dumps(resource_dict, indent=4)
            common_function.write_file(file_path=args.file,
                                       file_content=json_obj)
    except OSError:
        print(fail_info)
        sys.exit(2)
