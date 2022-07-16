# A description of what this class does
#
# @summary Get License Infomation
# @example ../../examples/license_get.pp
#
define rest::bmc::license::get (
  String $ibmc_username         = 'username',
  String $ibmc_password         = 'password',
  String $ibmc_host             = '127.0.0.1',
  String $ibmc_port             = '443',
  Optional[Boolean] $ignoreCert = undef,
) {


  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "getlicenseinfo"

  exec_urest { $title:
    command => "${script} ${command}",
    *       => $rest::service::context,
  }
}
