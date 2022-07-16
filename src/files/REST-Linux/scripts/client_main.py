# -*- coding:utf-8 -*-
"""
Function: client_main.py moudle. This moudle mainly involves the
init CLI command and Enabling Inband and Outband Channels function.
Copyright Information: xFusion Digital Technologies Co.,
 Ltd. All Rights Reserved © 2017-2021
"""
import os
import sys
import argparse
import signal
import re
import platform

from scripts import common_function

PROTOCOL_COMMAND = "setprotocol"
SET_CDEV_CHANNEL = "setcdevchannel"
SET_CDEV_COMMAND = "setcdevservice"
# add new interface
new_command_list = ["request", "addspdiagnose", "getspdiagnose", "collectsel",
                    "installlicense", "getlicenseinfo",
                    "restorefactory", "getsession",
                    "delsession", "resetraid", "addspdriveerasetask",
                    "getspdriveerasetask", SET_CDEV_COMMAND, "getcdevchannel",
                    SET_CDEV_CHANNEL, "delscreenshot", "getscreenshot",
                    "getprocessor", 'setuser',
                    common_function.HTTPS_SUB_COMMAND,
                    'delremotehttpsservercert', 'getsecurityservice',
                    'setsecurityservice']
# urest version
__version__ = '2.3.0'
inner_commands = [SET_CDEV_COMMAND, PROTOCOL_COMMAND]
# urest coordinate position of the help information.
POSITION_LENGTH = 30
# urest Inband and outband command flag
# (True indicates outband and False indicates inband).
flag = False
# subcommand and subcommand_init dict
met_dict = {}
# subcommand and subcommand's ArgumentParser dict
subparser_dic = {}
# subcommand  and submoudle's parameter_check dict
sub_parameter_check_dict = {}
# CLI command args's object
args = None
parser = None

new_script = ["get_processor.py", "get_cpu.py", "set_user.py",
              "import_remote_https_server_cert.py",
              "del_remote_https_server_cert.py",
              "get_security_service.py",
              "set_security_service.py"]

CERT_HELP = 'client ca certificate'
cur_path = os.path.split(os.path.realpath(__file__))[0]
root_path = os.path.dirname(cur_path)
ROOT_NAME = "Huawei Equipment Root CA.pem"
ROOT_NAME_XFUSION = "xFusionRootCA.crt"
IT_NAME = "Huawei IT Product CA.pem"
IT_NAME_XFUSION = "xfusion_ca.crt"
CA_DIR = "ibmc_client"
CLIENT_CA_NAME = "xfusion_it.pem"


class CHelpFormatter(argparse.HelpFormatter):
    """
    Function Description:Custom help formatter
    """

    def _iter_indented_subactions(self, action):
        self._max_help_position = POSITION_LENGTH
        self._action_max_length = POSITION_LENGTH

        try:
            get_subactions = action._get_subactions
        except AttributeError:
            pass
        else:
            self._indent()
            if isinstance(action, argparse._SubParsersAction):
                for subaction in sorted(get_subactions(),
                                        key=lambda x: x.dest):
                    yield subaction
            else:
                for subaction in get_subactions():
                    yield subaction
            self._dedent()

    def _format_actions_usage(self, actions, groups):
        """
        Function Description:Change '--timeout= TIMEOUT'
        in the help information to '--timeout=TIMEOUT'.
        Parameter:actions: helpactions
        groups: groups
        Return Value: text
        """
        text = super(CHelpFormatter, self)._format_actions_usage(actions,
                                                                 groups)
        if '--timeout= TIMEOUT' in text:
            text = text.replace('--timeout= TIMEOUT', '--timeout=TIMEOUT', 1)
        return text

    def _format_action(self, action):
        """
        Function Description:: Change '--timeout= TIMEOUT' in optional arguments
        in the help information to '--timeout=TIMEOUT '.
        Parameter: action: helpaction
        Return Value: text
        """
        text = super(CHelpFormatter, self)._format_action(action)
        if '--timeout= TIMEOUT' in text:
            text = text.replace('--timeout= TIMEOUT', '--timeout=TIMEOUT ', 1)
        return text


def set_cdev_service():
    """
    Function Description:set cdev service
    """
    from scripts import set_devirtualization_service
    if args.enable == "False":
        service_flag = set_devirtualization_service.close_server()
        if service_flag:
            print("Success: successfully completed request.")
            sys.exit(common_function.UREST_STATUS_CODE_0)
    else:
        service_flag = set_devirtualization_service.start_server_result(args)

    if not service_flag:
        sys.exit(common_function.UREST_STATUS_CODE_127)


def execute_subcommand(client):
    """
    Function Description:execute subcommand
    Parameter:client refishClient: class object
    """
    met = met_dict.get(args.subcommand)
    if met is not None:
        try:
            client.get_common_key()
            redfish_client.sub_command = args.subcommand
            result = met(client, args)
            common_function.set_exit_code(result)
        except common_function.CustomError as e:
            result = e.get_dict()
            common_function.get_error_info(result)
            common_function.set_exit_code(result)
        except KeyError as e:
            print(common_function.KEYERROR_FORMATTER.format("%s" % (e)))
            sys.exit(common_function.UREST_STATUS_CODE_127)


def init_communication_info(client):
    """
    Function Description:init communication channel
    Parameter:client refishClient: class object
    """
    if flag:
        client.set_auth()
    else:
        if args.subcommand == SET_CDEV_COMMAND:
            set_cdev_service()
        resp = client.set_inner_bmcinfo()
        if not resp:
            sys.exit(common_function.UREST_STATUS_CODE_127)


def exit_code_exit(error):
    """
    Function Description:Exit the program according to the exit code.
    Parameter:error int: exit code
    """
    if get_command_flag():
        sys.exit(error)
    elif "126" in str(error):
        if "Windows" in platform.system():
            sys.exit(common_function.UREST_STATUS_CODE_0)
        else:
            sys.exit(common_function.UREST_STATUS_CODE_2)
    else:
        sys.exit(common_function.UREST_STATUS_CODE_0)


def init_flag():
    """
    Function Description:initialization flag. The value can be False in inband
    and True in outband. Inband sessions are created.
    Modify: 2018.12.13 Modify the prompt information.
    2020.6.18 failed to create the in-band token. flag is True
    """
    global flag
    if "-H" in sys.argv and "setdns" not in sys.argv:
        flag = True
    elif "-H" in sys.argv and "setdns" in sys.argv \
            and sys.argv.index("-H") < sys.argv.index("setdns"):
        flag = True
    else:
        flag = False


def check_args():
    """
    Function Description:check inband and outband command
    """
    check_inband_command()
    check_outband_command()
    if args.subcommand is None:
        sys.exit(common_function.UREST_STATUS_CODE_0)
    check_subcommand()


def check_inband_command():
    """
    Function Description:check inband command
    """
    if not flag:
        if args.subcommand == SET_CDEV_CHANNEL:
            print('Failure: set the enabling status of the character device'
                  ' channel for communication between the uREST and iBMC.'
                  ' Use out-of-band commands only.')
            sys.exit(common_function.UREST_STATUS_CODE_127)

        if args.host is not None or \
                args.username is not None or \
                args.port is not None:
            # exit status code:126
            parser.error('-H, -U , -P and -p are not required for local access.'
                         ' -H, -U and -P are mandatory for remote access')


def check_outband_command():
    """
    Function Description:check outband command
    """
    if flag:
        if args.subcommand in inner_commands:
            parser.error('The subcommand only supports in-band operation')


def get_cert():
    """
    Function Description:get cert
    """
    try:
        ca_dir_path = os.path.join(root_path, CA_DIR)
        root_ca_path = os.path.join(ca_dir_path, ROOT_NAME)
        root_xfusion_ca_path = os.path.join(ca_dir_path, ROOT_NAME_XFUSION)
        it_ca_path = os.path.join(ca_dir_path, IT_NAME)
        it_xfusion_ca_path = os.path.join(ca_dir_path, IT_NAME_XFUSION)
        if (not os.path.exists(root_xfusion_ca_path) or not os.path.exists(it_xfusion_ca_path)) and \
                (not os.path.exists(root_ca_path) or not os.path.exists(it_ca_path)):
            print("%s%s" % (common_function.ERROR_KEY,
                            common_function.CERT_NOT_EXIT_MESSAGE.format(
                                ROOT_NAME_XFUSION, IT_NAME_XFUSION)))
            sys.exit(common_function.UREST_STATUS_CODE_127)
        client_ca_path = os.path.join(ca_dir_path, CLIENT_CA_NAME)
        client_xfusion_ca_content = ""
        if os.path.exists(root_xfusion_ca_path) and os.path.exists(it_xfusion_ca_path):
            with open(root_xfusion_ca_path, 'r+', encoding='utf-8') as root_xfusion_file:
                root_xfusion_ca_content = root_xfusion_file.read()
            with open(it_xfusion_ca_path, 'r+', encoding='utf-8') as it_xfusion_file:
                it_xfusion_ca_content = it_xfusion_file.read()
            client_xfusion_ca_content = "".join((it_xfusion_ca_content, root_xfusion_ca_content))
        client_ca_content = ""
        if os.path.exists(root_ca_path) and os.path.exists(it_ca_path):
            with open(root_ca_path, 'r+', encoding='utf-8') as root_file:
                root_ca_content = root_file.read()
            with open(it_ca_path, 'r+', encoding='utf-8') as it_file:
                it_ca_content = it_file.read()
            client_ca_content = "".join((it_ca_content, root_ca_content))
        content = "".join((client_xfusion_ca_content, client_ca_content))
        common_function.write_file(file_path=client_ca_path, file_content=content)
        return client_ca_path
    except OSError as message:
        print("%s%s" % (common_function.ERROR_KEY, message))
        sys.exit(common_function.UREST_STATUS_CODE_127)


def init_cert():
    """
    Function Description:CA certificate path for out-of-band initialization
    """
    if not flag or args.ignoreCert:
        args.cert = False
    elif args.cert is None:
        args.cert = get_cert()


def get_command_flag():
    """
    Function Description:get command_flag
    Parameter:subcommand str: subcommand
    code bool: check CLI command flag
    """
    if (args and (
            args.subcommand in new_command_list or args.code)) \
            or "--error-code" in sys.argv \
            or [sub_command for sub_command in new_command_list
                if sub_command in sys.argv]:
        return True

    return False


def init_met_subparser():
    """
    Function Description:init met_dict and subparser_dic
    """
    from importlib import import_module
    global met_dict
    global subparser_dic
    global sub_parameter_check_dict

    subparsers = parser.add_subparsers(title='sub commands',
                                       dest='subcommand',
                                       help='sub-command help',
                                       metavar="sub command")
    # Traverse the current folder, and add subcommands and parameters
    # based on the subcommand Python file names.
    for fil in os.listdir(cur_path):
        if (not os.path.isdir(fil)) \
                and (os.path.splitext(fil)[1] == '.py') \
                and (fil != '__init__.py') \
                and (fil != 'client_main.py') \
                and (fil != 'common_function.py'):
            mod = os.path.splitext(fil)[0]

            if fil in new_script:
                mod_split = mod.split(".py")
                mod_join = mod_split[-1]
            else:
                mod_split = mod.split("_")
                mod_join = ''.join(mod_split)

            mod_init = "%s%s" % (mod_join, '_init')
            mod_im = import_module(mod)
            met = getattr(mod_im, mod_join)
            met_init = getattr(mod_im, mod_init)
            sub_parameter_check = getattr(mod_im, 'check_parameter', None)
            sub_cmd = met_init(subparsers, subparser_dic)
            met_dict[sub_cmd] = met
            sub_parameter_check_dict[sub_cmd] = sub_parameter_check


def check_timeout(timeout):
    """
    Function Description:check CLI --timeout
    Parameter:subcommand str: subcommand
    timeout int: time out
    Return Value:timeout int: time out
    """
    time_out_object = re.search(r'(?P<timeout>^[\d]+$)', timeout)
    if time_out_object is None:
        message = 'invalid int value:\'%s\'' % str(timeout)
        parser.error(message)
    timeout_dic = time_out_object.groupdict()
    timeout = int(timeout_dic.get('timeout'))
    if timeout is not None:
        if '--timeout=%d' % timeout not in sys.argv \
                or timeout < 10 or timeout > common_function.MAX_TIMEOUT:
            message = 'Parameter timeout is invalid.' \
                      ' The timeout range 10-%s seconds.' \
                      % common_function.MAX_TIMEOUT
            parser.error(message)
    return timeout


def check_host(host):
    """
    Function Description:check CLI --H
    Parameter:host str: service's IP
    Return Value:host str: service's IP
    """
    if host:
        if host[-1] in ('#', '?') or ('/' in host):
            message = 'invalid BMC address.'
            parser.error(message)
    return host


def check_certificate(cert_path):
    """
    Function Description:check CLI --cert
    Parameter:cert_path str: CA's path
    """
    if cert_path is None or not os.path.exists(cert_path):
        parser.error("the certificate file %s does not exist." % cert_path)
    elif not os.path.isabs(cert_path):
        cert_path = os.path.abspath(cert_path)
    suffix = os.path.splitext(cert_path)[-1]
    if suffix not in (".crt", ".pem", ".cer"):
        parser.error('the certificate file format should '
                     'be .crt or .pem. or .cer')
    return cert_path


def parser_to_args():
    """
    Function Description:parser to args
    """
    global args
    try:
        args = parser.parse_args()
    except SystemExit as error:
        sys.exit(error)


def check_subcommand():
    """
    Function Description:check subcommand
    """
    if args.subcommand in common_function.SUBCOMMAND_RL_SERVER_LIST:
        common_function.check_real_path_parameter(
            subparser_dic[args.subcommand], args)
    sub_parameter_check = sub_parameter_check_dict.get(args.subcommand)
    if sub_parameter_check is not None:
        sub_parameter_check(subparser_dic[args.subcommand], args)


def init_args():
    """
    Function Description:init CLI command
    Modify: 2017.8.11 -h and -V respectively display the version number.
    2017.8.7 adjust the sequence of the -p and -P parameters.
    2018.12.20 translation-timeout help information
    """
    global parser
    parser = argparse.ArgumentParser(prog='urest', add_help=True,
                                     formatter_class=CHelpFormatter,
                                     description='urest version '
                                                 '%s' % __version__)
    parser.add_argument('-V', '--version', action='version',
                        version="uREST version %s" % __version__)
    parser.add_argument('--error-code', dest='code',
                        action='store_true',
                        help='exit code. When an error occurs, '
                             'the exit code is not 0.')
    parser.add_argument('-H', dest='host', required=flag,
                        type=check_host,
                        help='domain name, IPv4 address, '
                             'or [IPv6 address]')
    parser.add_argument('-p', dest='port', type=int,
                        help='port')
    parser.add_argument('-U', dest='username', required=flag,
                        help='local or LDAP username')
    parser.add_argument('-P', dest='password', required=flag,
                        help='password')
    parser.add_argument('-I', '--ignore-cert', dest='ignoreCert',
                        default=False, required=False,
                        action='store_true',
                        help='ignore certificate verification.')
    parser.add_argument('--timeout=', dest='timeout', type=check_timeout,
                        help='timeout interval (seconds) for '
                             'requesting the iBMC Redfish '
                             'interface [default=10].'
                             ' Upgrade commands [default=30] / '
                             'File commands [default=120].'
                             ' Other different timeouts are explained '
                             'in the specific commands.')
    # Modify: 2021.3.2 Added a prompt message.
    parser.add_argument('--cert', dest='cert',
                        type=check_certificate,
                        help=CERT_HELP)

    init_met_subparser()
    parser_to_args()
    check_args()
    init_cert()


def clientmain():
    """
    Function Description:CLI entry function
    Exception Description: SystemExit catch sys.exit()
    """
    client = None
    try:
        client = redfish_client.RedfishClient()
        init_data(client)
        init_communication_info(client)
        execute_subcommand(client)
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT,
                      exit_code_exit(common_function.UREST_STATUS_CODE_130))
    except (AttributeError, IOError, ImportError, IndexError, NameError,
            TypeError,
            ValueError, SystemError, KeyError) as e:
        print("Failure: %s" % str(e))
        exit_code_exit(common_function.UREST_STATUS_CODE_127)
    except SystemExit as error:
        exit_code_exit(error)
    finally:
        delete_inner_session(client)


def delete_inner_session(client):
    """
    Function Description:delete inband session
    Parameter:client refishClient: class object
    """
    if not flag and client is not None:
        client.delete_inner_session()


def init_data(client):
    """
    Function Description:init data
    Parameter:client refishClient: class object
    """
    if not flag and args.subcommand not in inner_commands:
        get_manufacturer_ipmi_id()
        client.create_inner_session()

    client.setself(args)


def get_manufacturer_ipmi_id():
    """
    Function Description: get vendor ipmi info of the manufacturer
    """
    import getbmctoken
    try:
        # 获取制造商ID的IPMI命令
        request_cmd = ["0x01", "0x03", "0x18", "0x00", "0x01"]
        res = getbmctoken.get_info_by_ipmi((common_function.format_byte_to_hex_stream(request_cmd)))
        if res is None or len(res) < 16:
            return

        # 12到14个byte是厂商ID
        common_function.VENDOR_IPMI_ID = [hex(i) for i in res[12:15]]
    except common_function.CustomError as error:
        print(error)
        sys.exit(common_function.UREST_STATUS_CODE_127)
    finally:
        pass


if __name__ == '__main__':
    # Modify: 2021/10/21 modifying the Maximum Recursion Depth of Python
    sys.setrecursionlimit(common_function.DEPTH_PYTHON)
    # Modify redfish_client.py's ibmcmode and ibmcip
    old_mode_ip = None
    try:
        init_flag()
        init_args()
        import redfish_client
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT,
                      exit_code_exit(common_function.UREST_STATUS_CODE_130))
    except SystemExit as error:
        exit_code_exit(error)
    except (TypeError, ValueError, ImportError) as e:
        print("Failure: %s" % e)
        exit_code_exit(common_function.UREST_STATUS_CODE_127)

    # Added urest exception handling mechanism.
    # Shielding the effects of SIGCHLD signals on programs in Linux systems
    try:
        old_handler = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    except AttributeError:
        pass
    clientmain()
    try:
        signal.signal(signal.SIGCHLD, old_handler)
    except AttributeError:
        pass
