# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include rest::service
define rest::user::get (
  $ibmc_username                    = 'username',
  $ibmc_password                    = 'password',
  $ibmc_host                        = '127.0.0.1',
  $ibmc_port                        = '443',
  Optional[String[1, 16]] $username = undef,
  Optional[Boolean] $ignoreCert     = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = $username ? {
    undef   => 'getuser',
    default => "getuser -N ${username}"
  }

  exec_urest { $title:
    command => "${script} ${command}",
    *       => $rest::service::context,
  }
}
