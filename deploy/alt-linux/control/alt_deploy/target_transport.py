"""Pinned administrative SSH prefix shared by fixed workstation receivers."""
import ipaddress


def ssh_prefix(settings,machine):
    address=str(ipaddress.ip_address(machine.ip))
    return ['/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ProxyCommand=none','-o','ProxyJump=none','-o','IdentitiesOnly=yes',
            '-o','IdentityAgent=none','-o','PermitLocalCommand=no','-o','LogLevel=ERROR',
            '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no',
            '-o','ControlMaster=no','-o','ControlPath=none','-o','UpdateHostKeys=no',
            '-o','VerifyHostKeyDNS=no','-o','HostKeyAlias='+address,
            '-o','GSSAPIAuthentication=no','-o','PreferredAuthentications=publickey',
            '-o','ConnectTimeout=3','-o','UserKnownHostsFile='+str(settings.known_hosts_file),
            '-i',str(settings.private_key_file),'ansible@'+address]
