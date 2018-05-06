title 'STIG'

control 'V-63375' do
  impact 1.0
  title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc 'Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63375'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\WinRM\Service') do
    it { should exist }
    its('DisableRunAs') { should eq 1 }
  end
end

control 'V-63657' do
  impact 1.0
  title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
  desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63657'
  describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    it { should exist }
    its('RestrictRemoteClients') { should eq 1 }
  end
end

control 'V-63669' do
  impact 1.0
  title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
  desc ''
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63669'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('InactivityTimeoutSecs') { should eq 900 }
  end
end

control 'V-63679' do
  impact 1.0
  title 'Administrator accounts must not be enumerated during elevation.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63679'
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
    it { should exist }
    its('EnumerateAdministrators') { should eq 0 }
  end
end

control 'V-63683' do
  impact 1.0
  title 'Windows Telemetry must be configured to the lowest level of data sent to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-08/finding/V-63683'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\DataCollection') do
    it { should exist }
    its('AllowTelemetry') { should eq 1 }
  end
end

control 'V-63705' do
  impact 1.0
  title 'InPrivate browsing in Microsoft Edge must be disabled.'
  desc 'The InPrivate browsing feature in Microsoft Edge prevents the storing of history, cookies, temporary Internet files, or other data. Disabling this feature maintains this data for review as necessary.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63705'
  describe registry_key('HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main') do
    it { should exist }
    its('AllowInPrivate') { should eq 0 }
  end
end

control 'V-63731' do
  impact 1.0
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.'
  desc 'Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63731'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    its('fDisableCdm') { should eq 1 }
  end
end

control 'V-63763' do
  impact 1.0
  title 'The Windows SMB client must be configured to always perform SMB packet signing.'
  desc 'The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63703'
  describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    its('RequireSecuritySignature') { should eq 1 }
  end
end

control 'V-63763' do
  impact 1.0
  title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'
  desc 'Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously vs. using the computer identity.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63763'
  describe registry_key('HKLM\System\CurrentControlSet\Control\LSA') do
    it { should exist }
    its('UseMachineId') { should eq 1 }
  end
end

control 'V-63765' do
  impact 1.0
  title 'NTLM must be prevented from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-10-28/finding/V-63765'
  describe registry_key('HKLM\System\CurrentControlSet\Control\LSA\MSV1_0') do
    it { should exist }
    its('allownullsessionfallback') { should eq 0 }
  end
end

control 'V-63767' do
  impact 1.0
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-10-28/finding/V-63767'
  describe registry_key('HKLM\System\CurrentControlSet\Control\LSA\pku2u') do
    it { should exist }
    its('AllowOnlineID') { should eq 0 }
  end
end

control 'V-63795' do
  impact 1.0
  title 'Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.'
  desc 'Certain encryption types are no longer considered secure. This setting configures a minimum encryption type for Kerberos, preventing the use of the DES and RC4 encryption suites.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63795'
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
    it { should exist }
    its('SupportedEncryptionTypes') { should eq 2_147_483_640 }
  end
end

control 'V-63803' do
  impact 1.0
  title 'The system must be configured to the required LDAP client signing level.'
  desc 'This setting controls the signing requirements for LDAP clients. This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63803'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LDAP') do
    it { should exist }
    its('LDAPClientIntegrity') { should eq 1 }
  end
end

control 'V-63577' do
  impact 1.0
  title 'Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares'
  desc 'Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in Hardened UNC paths before allowing access them. This aids in preventing tampering with or spoofing of connections to these paths.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63577'
  ref 'CIS L1 18.4.14.1'
  describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    it { should exist }
    its('\\\\*\NETLOGON') { should eq 'RequireMutualAuthentication=1,RequireIntegrity=1' }
    its('\\\\*\SYSVOL') { should eq 'RequireMutualAuthentication=1,RequireIntegrity=1' }
  end
end
