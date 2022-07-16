# A description of what this class does
#
# @summary Upgrade outband firmware
#
# @example
#   ../../../examples/firmware_outband_upgrade.pp
#
define rest::firmware::outband::upgrade (
  $ibmc_username                = 'username',
  $ibmc_password                = 'password',
  $ibmc_host                    = '127.0.0.1',
  $ibmc_port                    = '443',
  $firmware_file_uri            = undef,
  Optional[Boolean] $ignoreCert = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }
  $param = $firmware_file_uri ? {
    /^https\:|^scp\:|^sftp\:|^cifs\:|^nfs\:/ => "-i '${firmware_file_uri}'",
    default => "-F '${firmware_file_uri}'"
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "upgradefw '${param}'"

  warning("Upgrade outband firmware may takes a long time, please be patient.")

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
    timeout => 0,
  }

}
