# A description of what this class does
#
# @summary Disconnect Virtual Media
#
define rest::bmc::vmm::disconnect (
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
  $command = "connectvmm -T Disconnect"

  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }
}
