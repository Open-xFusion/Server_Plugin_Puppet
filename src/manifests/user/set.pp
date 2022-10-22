# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include rest::service
define rest::user::set (
  $ibmc_username                              = 'username',
  $ibmc_password                              = 'password',
  $ibmc_host                                  = '127.0.0.1',
  $ibmc_port                                  = '443',
  String[1, 16] $username                     = undef,
  Optional[String[1, 16]] $newusername        = undef,
  Optional[String[1, 20]] $newpassword        = undef,
  Optional[Rest::UserRole] $newrole           = undef,
  Optional[Boolean] $enabled                  = undef,
  Optional[Boolean] $locked                   = undef,
  Optional[String[1, 16]] $snmpV3AuthProtocol = undef,
  Optional[String[1, 16]] $snmpV3PrivProtocol = undef,
  Optional[String[1, 20]] $encryptionPassword = undef,
  Optional[Boolean] $ignoreCert               = undef,
) {

  # init rest
  include ::rest

  $ignore_cert = $ignoreCert ? {
    true    => '--ignore-cert',
    default => ''
  }

  $params = {
    '-UN'      => $newusername ? {
      undef   => undef,
      default => $newusername
    },
    '-P'      => $newpassword ? {
      undef   => undef,
      default => $newpassword
    },
    '-R'      => $newrole ? {
      undef   => undef,
      default => $newrole
    },
    '-E'    => $enabled ? {
      undef   => undef,
      default => bool2str($enabled, 'True', 'False')
    },
    '-SAP'  => $snmpV3AuthProtocol ? {
      undef   => undef,
      default => $snmpV3AuthProtocol
    },
    '-SPP'  => $snmpV3PrivProtocol ? {
      undef   => undef,
      default => $snmpV3PrivProtocol
    },
    '-SEP'  => $encryptionPassword ? {
      undef   => undef,
      default => $encryptionPassword
    }
  }

  $locked2  = $locked ? {
    undef   => '',
    default => '-L False'
  }

  $joined = join(join_keys_to_values(delete_undef_values($params), "' '"), "' '")
  $script = "sh rest -H '${ibmc_host}' -p ${ibmc_port} -U '${ibmc_username}' -P '${ibmc_password}' --error-code $ignore_cert"
  $command = "setuser -N ${username} '${joined}' ${locked2}"


  exec_urest { $title:
    command => Sensitive.new("${script} ${command}"),
    *       => $rest::service::context,
  }
}
