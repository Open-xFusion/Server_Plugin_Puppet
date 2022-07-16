# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include rest::service
define rest::bios::boot::order (
  String $ibmc_username          = 'username',
  String $ibmc_password          = 'password',
  String $ibmc_host              = '127.0.0.1',
  String $ibmc_port              = '443',
  Array[Rest::BootSeq] $sequence = undef,
  Optional[Boolean] $ignoreCert  = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  # convert sequence to string
  $joined = join($sequence, ' ')
  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "setsysboot -Q ${joined}"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }

}
