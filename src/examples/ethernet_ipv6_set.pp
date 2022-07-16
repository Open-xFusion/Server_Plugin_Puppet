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

  # load hosts from hiera data-source
  $hosts = lookup('hosts')

  # address_origin -> Enum['Static', 'DHCPv6']

  # interate all hosts and get bios
  $hosts.each | String $hostname, Hash $data | {
    rest::bmc::ethernet::ipv6 { $hostname:
      ibmc_host      => $hostname,
      ibmc_username  => $data['username'],
      ibmc_password  => $data['password'],
      ip             => '192:168::2019',
      gateway        => '192:168::1',
      prefix_length  => 64,
      address_origin => 'Static',
      ignoreCert    =>  false,
    }
  }
}
