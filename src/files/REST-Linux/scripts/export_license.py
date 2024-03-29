#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Function:Install license
Date:2018.12.13
"""
import errno
import os
import stat
import sys
import time

from scripts import common_function

Export_To_HELP = '''
The license file URI to be export to.
Export to file path could be the BMC local path URI (under /tmp directory), 
or remote path URI (protocols HTTPS, SFTP, NFS, CIFS, and SCP are supported).
'''

# Sadly, Python fails to provide the following magic number for us.
ERROR_INVALID_NAME = 123
'''
Windows-specific error code indicating an invalid pathname.

See Also
----------
https://msdn.microsoft.com/en-us/library/windows/desktop/ms681382%28v=vs.85%29.aspx
    Official listing of all such codes.
'''


def is_pathname_valid(pathname):
    '''
    `True` if the passed pathname is a valid pathname for the current OS;
    `False` otherwise.
    '''
    # If this pathname is either not a string or is but is empty, this pathname
    # is invalid.
    try:
        if not isinstance(pathname, str) or not pathname:
            return False

        # Strip this pathname's Windows-specific drive specifier (e.g., `C:\`)
        # if any. Since Windows prohibits path components from containing `:`
        # characters, failing to strip this `:`-suffixed prefix would
        # erroneously invalidate all valid absolute Windows pathnames.
        _, pathname = os.path.splitdrive(pathname)

        # Directory guaranteed to exist. If the current OS is Windows, this is
        # the drive to which Windows was installed (e.g., the "%HOMEDRIVE%"
        # environment variable); else, the typical root directory.
        root_dirname = os.environ.get('HOMEDRIVE', 'C:') \
            if sys.platform == 'win32' else os.path.sep

        # Append a path separator to this directory if needed.
        root_dirname = root_dirname.rstrip(os.path.sep) + os.path.sep

        # Test whether each path component split from this pathname is valid or
        # not, ignoring non-existent and non-readable path components.
        for pathname_part in pathname.split(os.path.sep):
            try:
                os.lstat(root_dirname + pathname_part)
            # If an OS-specific exception is raised, its error code
            # indicates whether this pathname is valid or not. Unless this
            # is the case, this exception implies an ignorable kernel or
            # filesystem complaint (e.g., path not found or inaccessible).
            #
            # Only the following exceptions indicate invalid pathnames:
            #
            # * Instances of the Windows-specific "WindowsError" class
            #   defining the "winerror" attribute whose value is
            #   "ERROR_INVALID_NAME". Under Windows, "winerror" is more
            #   fine-grained and hence useful than the generic "errno"
            #   attribute. When a too-long pathname is passed, for example,
            #   "errno" is "ENOENT" (i.e., no such file or directory) rather
            #   than "ENAMETOOLONG" (i.e., file name too long).
            # * Instances of the cross-platform "OSError" class defining the
            #   generic "errno" attribute whose value is either:
            #   * Under most POSIX-compatible OSes, "ENAMETOOLONG".
            #   * Under some edge-case OSes (e.g., SunOS, *BSD), "ERANGE".
            except OSError as exc:
                if hasattr(exc, 'winerror'):
                    if exc.winerror == ERROR_INVALID_NAME:
                        return False
                elif exc.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
                    return False
    # If a "TypeError" exception was raised, it almost certainly has the
    # error message "embedded NUL character" indicating an invalid pathname.
    except TypeError as exc:
        return False
    # If no exception was raised, all path components and hence this
    # pathname itself are valid. (Praise be to the curmudgeonly python.)
    else:
        return True
    # If any other exception was raised, this is an unrelated fatal issue
    # (e.g., a bug). Permit this exception to unwind the call stack.
    #
    # Did we mention this should be shipped with Python already?


def is_path_creatable(pathname):
    '''
    `True` if the current user has sufficient permissions to create the passed
    pathname; `False` otherwise.
    '''
    # Parent directory of the passed path. If empty, we substitute the current
    # working directory (CWD) instead.
    dirname = os.path.dirname(pathname) or os.getcwd()
    return os.access(dirname, os.W_OK)


def is_file_exists_or_creatable(pathname):
    '''
    `True` if the passed pathname is a valid pathname for the current OS _and_
    either currently exists or is hypothetically creatable; `False` otherwise.

    This function is guaranteed to _never_ raise exceptions.
    '''
    try:
        # To prevent "os" module calls from raising undesirable exceptions on
        # invalid pathnames, is_pathname_valid() is explicitly called first.
        return is_pathname_valid(pathname) and not os.path.isdir(pathname) and (
            os.path.exists(pathname) or is_path_creatable(pathname))
    # Report failure on non-fatal filesystem complaints (e.g., connection
    # timeouts, permissions issues) implying this path to be inaccessible. All
    # other exceptions are unrelated fatal issues and should not be caught here.
    except OSError:
        return False


def exportlicense_init(parser, parser_list):
    """
    :Function:Install license subcommand
    :param parser:major command argparser
    :param parser_list:save subcommand parser list
    :return:
    """
    sub_parser = parser.add_parser('exportlicense',
                                   help='''export license''')
    sub_parser.add_argument('-T', dest='exportTo',
                            type=str,
                            required=True,
                            help=Export_To_HELP)
    parser_list['exportlicense'] = sub_parser
    return 'exportlicense'


def exportlicense(client, args):
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
        return None

    url = "/redfish/v1/Managers/%s/LicenseService" \
          "/Actions/LicenseService.ExportLicense" % slotid
    # Construct payload.
    payload = {
        "Type": "URI",
        "Content": args.exportTo
    }

    # treat it as local file
    is_local_file_path, payload = _check_image_uri(payload, args)

    resp = client.create_resource(url, payload)
    if resp is None:
        return None

    if resp.get('status_code') == 202:
        time.sleep(1)
        resp_task = client.print_task_prog(resp)
        if resp_task is None:
            return None

        if resp_task == 'Exception':
            _resptaskparse(resp, client)
            sys.exit(144)
    if resp['status_code'] == 200:
        if is_local_file_path:
            # download bmc file
            _payload = {
                "TransferProtocol": "HTTPS",
                "Path": payload.get('Content')
            }
            download_url = "/redfish/v1/Managers/%s" \
                "/Actions/Oem/%s/Manager.GeneralDownload" % (slotid, common_function.COMMON_KEY)
            # Because license file is small, so we just keep it in memory directly ....
            resp = client.create_resource(download_url, _payload)
            if resp is not None and resp.get('status_code') < 300:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                modes = stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
                with os.fdopen(os.open(args.exportTo, flags, modes), 'wb') as file:
                    file.write(resp.get('resource'))
            else :
                print("Failure: failed to download file to %s from BMC" % args.exportTo)
                sys.exit(144)

        print('Success: successfully completed request')
        return resp
    else:
        info = resp['message']['error']['@Message.ExtendedInfo'][0]
        message_id = info.get('MessageId')
        if 'Format' in message_id:
            print('Failure: import failed due to invalid path')
        else:
            message = (info.get('Message')).lower()
            print('Failure: ' + message[:-1])

    return resp


def _check_image_uri(payload, args):
    is_local_file_path = False
    image_uri = args.exportTo
    if is_file_exists_or_creatable(image_uri):
        if str(image_uri).split('.')[-1] != 'xml':
            print('Failure: license file type should be \'.xml\'')
            return None

        if str(image_uri).split('/')[-1] == image_uri:
            filename = str(image_uri).split("\\")[-1]
        else:
            filename = str(image_uri).split('/')[-1]
        is_local_file_path = True
        payload['Content'] = ('/tmp/web/' + filename)
    else:
        protocol = None
        protocol_list = ['https', 'scp', 'sftp', 'cifs', 'nfs']
        for item in protocol_list:
            if image_uri.lower().startswith(item + "://"):
                lower_scheme = image_uri[:len(item)].lower()
                image_uri = lower_scheme + image_uri[len(item):]
                protocol = item.upper()
                payload['Content'] = (image_uri)
                break

        if protocol is None:
            message = ('Failure: File Uri %s is not exits or not supported, '
                       'file transfer protocols should be one of %s.')
            print(message % (image_uri, ','.join(protocol_list)))
            return None
    return is_local_file_path, payload


def _resptaskparse(resp, client):
    """
    :Function:Handle exception task state
    :param client:RedfishClient object
    :param resp:response information
    :return:
    """

    taskid = resp['resource']['@odata.id']

    sys_resp = client.get_resource(taskid)
    if sys_resp is None:
        sys.exit(127)

    if sys_resp['status_code'] != 200:
        info = sys_resp['message']['error']['@Message.ExtendedInfo'][0]
        message = (info['Message']).lower()
        print('Failure: ' + message[:-1])
    else:
        # Return the task failure details
        message = (sys_resp['resource']['Messages']['Message']).lower()
        print('Failure: ' + message[:-1])



if __name__ == '__main__':
    print(is_file_exists_or_creatable('/home/qianbiao'))