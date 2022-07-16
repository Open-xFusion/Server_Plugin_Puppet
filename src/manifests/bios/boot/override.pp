# A description of what this class does
#
# @summary Set Boot Source Override
#
# @example
#   include rest::service
define rest::bios::boot::override (
  $ibmc_username                 = 'username',
  $ibmc_password                 = 'password',
  $ibmc_host                     = '127.0.0.1',
  $ibmc_port                     = '443',
  Rest::BootSource $target       = undef,
  Rest::BootEnabled $enabled     = undef,
  Optional[Rest::BootMode] $mode = undef,
  Optional[Boolean] $ignoreCert  = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }
  $params = {
    '-T'  => $target,
    '-TS' => $enabled,
    '-M'  => $mode,
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $joined = join(join_keys_to_values(delete_undef_values($params), "' '"), "' '")
  $command = "setsysboot '${joined}'"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }

}
