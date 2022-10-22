# A description of what this resource does
#
# @summary Send a request what's url is custom to BMC.
#
# @example
#   ../../examples/common_interface_request.pp
define rest::common_interface (
  $ibmc_username                      = 'username',
  $ibmc_password                      = 'password',
  $ibmc_host                          = '127.0.0.1',
  $ibmc_port                          = '443',
  String $url                         = undef,
  Rest::RequestType $type             = undef,
  Optional[String] $request_body_file = undef,
  Optional[String] $file              = undef,
  Optional[Boolean] $ignoreCert       = undef,
) {

  # init rest
  include ::rest

  $requestBodyFile = $request_body_file ? {
    undef   => "",
    default => "-B ${request_body_file}"
  }

  $exportFile = $file ? {
    undef   => "",
    default => "-F ${file}"
  }

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "request -I ${url} -T ${type} ${requestBodyFile} ${exportFile}"

  exec_urest { $title:
    command => "${script} ${command}",
    *       => $rest::service::context,
  }

}