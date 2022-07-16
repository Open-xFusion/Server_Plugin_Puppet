# A description of what this class does
#
# @summary Set SP properties
#
# @example
#   ../../../examples/os_install_config.pp
#
define rest::system::deploy::config (
  $ibmc_username                     = 'username',
  $ibmc_password                     = 'password',
  $ibmc_host                         = '127.0.0.1',
  $ibmc_port                         = '443',
  String $os_deploy_config_file_path = undef,
  Optional[Boolean] $ignoreCert      = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "addspcfg -T SPOSInstallPara -F '${os_deploy_config_file_path}'"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }

}
