# -*- coding:utf-8 -*-
"""
Function: getbmcinfo.py moudle. This moudle mainly involves the
Obtaining BMC Information function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2018-2021
"""
import os
import sys

from scripts.common_function import BMA_BIN_PATH

from scripts import common_function

BMC_IP = 'FE80:0000:0000:0000:9E7D:A3FF:FE28:6FFA'
BMC_ETHNAME = 'veth'
BMC_PORT = 40443


def getinnerhost(mode, bmc_ip):
    """
    #=====================================================================
    #   @Method:  获取带内bmc的IP地址函数
    #   @Param:
    #   @Return: host:带内访问bmc的IP地址 带[]
    #=====================================================================
    """
    host = ""
    if mode == "IPv6":
        host = r'[%s%%%s]' % (BMC_IP, BMC_ETHNAME)
    if mode == "IPv4":
        host = r'%s' % bmc_ip
    return host


def getinnerport():
    """
    #=====================================================================
    #   @Method:  获取带内bmc的端口号函数
    #   @Param:
    #   @Return: BMC_PORT:带内访问bmc的端口号
    #=====================================================================
    """
    return BMC_PORT


def getinnerheaderhost(mode, bmc_ip):
    """
    #=====================================================================
    #   @Method:  获取带内bmc的IP地址函数
    #   @Param:
    #   @Return: host:带内访问bmc的IP地址 不带[]
    #=====================================================================
    """
    headerhost = ""
    if mode == "IPv6":
        headerhost = r'%s%%%s' % (BMC_IP, BMC_ETHNAME)
    if mode == "IPv4":
        headerhost = r'%s' % bmc_ip
    return headerhost


def get_usb():
    """
    Function Description:get usb
    Return Value:bool
    """
    return os.path.exists(common_function.USB_DEV_FILE)


def get_devirtualization():
    """
    Function Description:Check whether the VM is devirtualized.
     If True is returned, the VM is devirtualized.
      If False is returned, the VM is virtualized.
    Return Value:bool
    """
    if os.path.exists("/sys/module/cdev_veth_drv"):
        return True
    return False


def get_devirtual_port():
    """
    Function Description:Obtaining the iBMC Port for Devirtualization
    """
    cur_path = os.path.split(os.path.realpath(__file__))[0]
    urest_path = os.path.dirname(cur_path)
    manager_path = os.path.join(urest_path, 'tools/manager')
    bma_tool_path = os.path.join(BMA_BIN_PATH, "manager")

    if os.path.exists(bma_tool_path):
        command = "%s list | grep 40443 | awk \'{print $3}\'" % bma_tool_path
    elif os.path.exists(manager_path):
        command = "%s list | grep 40443 | awk \'{print $3}\'" % manager_path
    else:
        raise common_function.CustomError("Failure：failed to"
                                          " get port number.")

    try:
        virtual_info = common_function.get_cmd_value(command=command)
    except common_function.CustomError as e:
        print("Failure: %s" % str(e))
        sys.exit(common_function.UREST_STATUS_CODE_127)

    flag = common_function.is_success(virtual_info)
    if not flag:
        raise common_function.CustomError(
            virtual_info.get(common_function.ERROR))

    virtual_port = virtual_info.get("Result")
    return int(virtual_port)
