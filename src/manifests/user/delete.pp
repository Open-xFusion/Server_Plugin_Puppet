# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include rest::service
define rest::user::delete (
  $ibmc_username                = 'username',
  $ibmc_password                = 'password',
  $ibmc_host                    = '127.0.0.1',
  $ibmc_port                    = '443',
  $username                     = undef,
  Optional[Boolean] $ignoreCert = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "deluser -N ${username}"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }
}
