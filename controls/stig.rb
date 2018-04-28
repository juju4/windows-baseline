title 'STIG'

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
