title 'STIG'

control 'V-63679' do
  impact 1.0
  title 'Administrator accounts must not be enumerated during elevation.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63679'
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
    it { should exist }
    its('EnumerateAdministrators') { should eq '0' }
  end
end

control 'V-63683' do
  impact 1.0
  title 'Windows Telemetry must be configured to the lowest level of data sent to Microsoft.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-08/finding/V-63683'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows\DataCollection') do
    it { should exist }
    its('AllowTelemetry') { should eq '1' }
  end
end

control 'V-63731' do
  impact 1.0
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63731'
  describe registry_key('HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    its('fDisableCdm') { should eq '1' }
  end
end

control 'V-63763' do
  impact 1.0
  title 'The Windows SMB client must be configured to always perform SMB packet signing.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63703'
  describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should exist }
    its('RequireSecuritySignature') { should eq '1' }
  end
end

control 'V-63763' do
  impact 1.0
  title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63763'
  describe registry_key('HKLM\System\CurrentControlSet\Control\LSA') do
    it { should exist }
    its('UseMachineId') { should eq '1' }
  end
end

control 'V-63765' do
  impact 1.0
  title 'NTLM must be prevented from falling back to a Null session.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-10-28/finding/V-63765'
  describe registry_key('HKLM\System\CurrentControlSet\Control\LSA\MSV1_0') do
    it { should exist }
    its('allownullsessionfallback') { should eq '0' }
  end
end

control 'V-63767' do
  impact 1.0
  title 'PKU2U authentication using online identities must be prevented.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-10-28/finding/V-63767'
  describe registry_key('HKLM\System\CurrentControlSet\Control\LSA\pku2u') do
    it { should exist }
    its('AllowOnlineID') { should eq '0' }
  end
end

control 'V-63803' do
  impact 1.0
  title 'The system must be configured to the required LDAP client signing level.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63803'
  describe registry_key('HKLM\System\CurrentControlSet\Services\LDAP') do
    it { should exist }
    its('LDAPClientIntegrity') { should eq '1' }
  end
end

control 'V-63577' do
  impact 1.0
  title 'Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63577'
  describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
    it { should exist }
    its('\\*\NETLOGON') { should eq 'RequireMutualAuthentication=1, RequireIntegrity=1' }
    its('\\*\SYSVOL') { should eq 'RequireMutualAuthentication=1, RequireIntegrity=1' }
  end
end
