# The baseline for module testing used by Puppet Inc. is that each manifest
# should have a corresponding test manifest that declares that class or defined
# type.
#
# Tests are then run by using puppet apply --noop (to check for compilation
# errors and view a log of events) or by fully applying the test in a virtual
# environment (to compare the resulting system state to the desired state).
#
# Learn more about module testing here:
# https://puppet.com/docs/puppet/latest/bgtm.html#testing-your-module
#
node default {
  # Function: Provide common interface.
  # Please refer to the user's Guide for the path and detailed usage of redfish request resources.

  # load hosts from hiera data-source
  $hosts = lookup('hosts')

  # url: The request url. Required.
  # type: HTTP request type. Select one from {GET, POST, PATCH, DELETE}. Required.
  # request_body_file: The request message body is a required parameter when the request type is POST or PATCH.
  #     It's an optional parameter when the request type is GET or DELETE.
  # file: The path to save the obtained request result to the local location. Optional.
  # ignoreCert: If ignore certificate verification. {true, else} default false

  $hosts.each | String $hostname, Hash $data | {
    rest::common_interface { $hostname:
      ibmc_host         => $hostname,
      ibmc_username     => $data['username'],
      ibmc_password     => $data['password'],
      url               => $data['url'],
      type              => $data['type'],
      request_body_file => undef,
      file              => undef,
      ignoreCert        => false,
    }
  }
}
