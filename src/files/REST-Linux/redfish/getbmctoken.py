# -*- coding:utf-8 -*-
"""
Function: getbmctoken.py moudle. This moudle mainly involves the
 obtaining BMC Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2021
"""
import os
import stat
import sys
import time
from scripts import common_function

XARGS = ["0x30", "0x94", "0x14", "0xe3", "0x00", "0x39", "0x04",
         "0x01", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
         "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
         "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
         "0x00", "0x00"]
SEQ = 0x00
# Number of bytes read from USB character device file
USB_BYTES_NUMBER = 512


def openDevice(path):
    """
    Function Description: open character device file
    Parameter:path str: file path
    Modify: 2021.08.31 secbrella clears 0.
    """
    fd = None
    if os.path.exists(path):
        open_file_flags = os.O_RDWR | os.O_APPEND | os.O_EXCL
        modes = stat.S_IRUSR | stat.S_IWUSR
        try:
            fd = os.open(path, open_file_flags, modes)
        except BaseException as e:
            raise common_function.CustomError(str(e))
    return fd


def closeDevice(fd):
    """
    #==========================================================================
    #   @Method:
    #   @Param:
    #   @Return:
    #==========================================================================
    """
    try:
        if fd is not None:
            os.close(fd)
    except BaseException as e:
        raise common_function.CustomError(str(e))


def writeDevice(fd, data):
    """
    #==========================================================================
    #   @Method:
    #   @Param:
    #   @Return:
    #==========================================================================
    """
    try:
        os.write(fd, data)
    except BaseException as e:
        raise common_function.CustomError(str(e))


def read(fd, byte_num):
    """
    Function Description:Read data from a character device
    Parameter:fd int:file identifier
    Return Value:data bytes:file content
    """
    readTimes = 0
    data = None
    try:
        while readTimes < common_function.READ_CHARACTER_DEVICE_TIMEOUT:
            data = os.read(fd, byte_num)
            if data:
                break
            readTimes += 1
            time.sleep(common_function.INTERVAL_TIME)
    except BaseException as e:
        raise common_function.CustomError(str(e))

    return data


def waitDataReady(fd):
    """
    #==========================================================================
    #   @Method:  
    #   @Param:
    #   @Return:
    #==========================================================================
    """
    from select import epoll, EPOLLIN, EPOLLRDNORM
    ready = False

    try:
        ep = epoll()
        ep.register(fd, EPOLLIN | EPOLLRDNORM)
        times = 10
        while not ready and times > 0:
            try:
                events = ep.poll(1)
                # Modify: 2019.10.28 BMC链接异常，超时处理
                len_events = len(events)
                if events is None or len_events == 0:
                    # Modify: 2020.04.01 vmware 带内命令异常
                    time.sleep(1)
                    times = times - 1
                    continue
                ready = get_ready(events, fd)
            except (IOError, OSError):
                times = times - 1
                continue
    finally:
        if ep is not None:
            ep.unregister(fd)
            ep.close()

    return ready


def get_ready(events, fd):
    """
    Function Description:get ready
    Parameter:events tuple
              fd object
    Return Value:In-band ready indication
    """
    from select import EPOLLIN, EPOLLRDNORM

    for (fileno, event) in events:
        if fileno == fd and event & (EPOLLIN | EPOLLRDNORM):
            return True
    return False


def get_token(data):
    """
    Function Description:get token
    Parameter:data bytes:file content
    Return Value:token str:authenticate
    """
    token = None
    if data is not None:
        ll = [x for x in data[9:-1]]
        token = ("%s" % ("".join("%c" % (x) for x in ll)))
    return token


def get_inner_session():
    """
    Function Description:get inner session
    Return Value:token str:token
    """
    return get_token(get_info_by_ipmi(get_command()))


def get_info_by_ipmi(command):
    """
    Function Description: communication by ipmi
    Parameter:command str:ipmi command
    Return Value:data str:ipmi response
    """
    if command is None:
        print("ipmi command can not be empty")
        return
    if os.path.exists(common_function.USB_DEV_FILE):
        service_type = common_function.USB_DEVICE
    elif os.path.exists(common_function.NOWIN_PCIE_DEV_FILE):
        service_type = common_function.PCIE_DEVICE
    else:
        raise common_function.CustomError(
            common_function.CDEVICE_NOT_EXIT_MESSAGE)
    file_path = common_function.SERVICE_TYPE_FILE.get(service_type)
    end_count = common_function.RETRY_COUNT + 2
    for i in range(1, end_count):
        data = None
        fd = None
        try:
            fd = openDevice(file_path)
            time.sleep(1)
            writeDevice(fd, command)
            if service_type == common_function.PCIE_DEVICE and \
                    waitDataReady(fd):
                data = read(fd, common_function.PCIE_BYTES_NUMBER)
            elif service_type == common_function.USB_DEVICE:
                data = read(fd, USB_BYTES_NUMBER)
            if data is not None:
                return data
        except common_function.CustomError:
            continue
        finally:
            try:
                closeDevice(fd)
            except common_function.CustomError:
                continue
    raise common_function.CustomError(common_function.DEVICE_ERROR_MESSAGE)


def get_command():
    """
    Function Description:get ipmi command
    Return Value:command str:ipmi command
    Modify: 2017.8.7 Deleted the debugging code of the function for
            obtaining the BMC token in in-band mode.
    """
    XARGS[2:5] = common_function.VENDOR_IPMI_ID
    shift = 0
    # shift left, if little order,
    if sys.byteorder.lower() == "little":
        shift = 2

    header = [0x00, 0x00, 0x00, 0x00, 0x00]
    header[0] = "0x%x" % (0x01)
    header[1] = "0x%x" % (len(XARGS) + 1)
    header[2] = "0x%x" % (int(XARGS[0], 16) << shift)
    header[3] = "0x%x" % (SEQ)
    header[4] = "0x%x" % (int(XARGS[1], 16))

    command = XARGS[2:]
    command = header + command
    return common_function.format_byte_to_hex_stream(command)
