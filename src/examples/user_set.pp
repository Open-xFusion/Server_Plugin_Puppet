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

  # new user role available values:
  #   "Administrator", "Operator", "Commonuser", "NoAccess",
  #   "CustomRole1", "CustomRole2", "CustomRole3", "CustomRole4"

  # interate all hosts and get bios
  $hosts.each | String $hostname, Hash $data | {
    rest::user::set { "$hostname":
      ibmc_host          => "$hostname",
      ibmc_username      => "${data['username']}",
      ibmc_password      => "${data['password']}",
      username           => "${data['old-user-name']}",
      newusername        => "${data['user-set-name']}",
      newpassword        => "${data['user-set-password']}",
      encryptionPassword => "${data['user-snmpv3-password']}",
      newrole            => "Operator",
      snmpV3AuthProtocol => "MD5",
      snmpV3PrivProtocol => "AES",
      enabled            => false,
      locked             => true,
      ignoreCert         => false,
    }
  }
}
