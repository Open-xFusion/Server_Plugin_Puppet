# A description of what this class does
#
# @summary Set chassis indicator LED state
#
# @example
#   ../../examples/indicator_led_set.pp
#
define rest::chassis::led::set (
  $ibmc_username                 = 'username',
  $ibmc_password                 = 'password',
  $ibmc_host                     = '127.0.0.1',
  $ibmc_port                     = '443',
  Rest::IndicatorLEDState $state = undef,
  Optional[Boolean] $ignoreCert  = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "setindicatorled -S ${state}"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }
}
