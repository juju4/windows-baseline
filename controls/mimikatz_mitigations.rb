
title 'Mimikatz mitigations'

control 'mimikatz-101' do
  impact 1.0
  title 'Mimikatz mitigations'
  desc 'Ensure mitigations against Mimikatz and Pass-the-Hash attacks are in place'
  ref url: 'https://jimshaver.net/2016/02/14/defending-against-mimikatz/'
  ref url: 'http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/'
  describe registry_key('HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest') do
    it { should exist }
    its('UseLogonCredential') { should eq 0 }
  end
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should exist }
    its('FilterAdministratorToken') { should eq 1 }
    its('LocalAccountTokenFilterPolicy') { should eq 0 }
  end
end
