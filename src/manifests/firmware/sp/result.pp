# A description of what this class does
#
# @summary Get SP Result
#
# @example
#   ../../../examples/firmware_sp_result_get.pp
#
define rest::firmware::sp::result (
  $ibmc_username                = 'username',
  $ibmc_password                = 'password',
  $ibmc_host                    = '127.0.0.1',
  $ibmc_port                    = '443',
  Optional[Boolean] $ignoreCert = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = 'getspresult'

  exec_urest { $title:
    command => "${script} ${command}",
    *       => $rest::service::context,
  }

}
