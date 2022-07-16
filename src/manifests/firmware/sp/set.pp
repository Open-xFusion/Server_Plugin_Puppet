# A description of what this class does
#
# @summary Set SP properties
#
# @example
#   ../../../examples/set_set.pp
#
define rest::firmware::sp::set (
  $ibmc_username                           = 'username',
  $ibmc_password                           = 'password',
  $ibmc_host                               = '127.0.0.1',
  $ibmc_port                               = '443',
  Boolean $start_enabled                   = undef,
  Integer[1] $system_restart_delay_seconds = undef,
  Optional[Boolean] $finished              = undef,
  Optional[Integer[300, 86400]] $timeout   = undef,
  Optional[Boolean] $ignoreCert            = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $params = {
    '-S' => $start_enabled ? {
      undef   => undef,
      default => bool2str($start_enabled, 'True', 'False'),
    },
    '-T' => $system_restart_delay_seconds,
    '-F' => $finished ? {
      undef   => undef,
      default => bool2str($start_enabled, 'True', 'False'),
    },
    '-O' => $timeout,
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"

  $joined = join(join_keys_to_values(delete_undef_values($params), "' '"), "' '")
  $command = "setspinfo '${joined}'"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }

}
