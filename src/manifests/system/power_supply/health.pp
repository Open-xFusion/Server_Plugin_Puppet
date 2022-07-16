# A description of what this class does
#
# @summary Get PSU Health
#
# @example
#   ../../../examples/power_supply_health_get.pp
#
define rest::system::power_supply::health (
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
  $command = 'getpsuhealth'

  exec_urest { $title:
    command => "${script} ${command}",
    *       => $rest::service::context,
  }

}
