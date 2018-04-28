
title 'User Rights Assignment'

control 'cis-access-cred-manager-2.2.1' do
  impact 0.7
  title '2.2.1 Set Access Credential Manager as a trusted caller to No One'
  desc 'Set Access Credential Manager as a trusted caller to No One'
  tag cis: ['windows_2012r2:2.2.1', 'windows_2016:2.2.1', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-network-access-2.2.2' do
  impact 0.7
  title '2.2.2 Set Access this computer from the network'
  desc 'Set Access this computer from the network'
  tag cis: ['windows_2012r2:2.2.2', 'windows_2016:2.2.2', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeNetworkLogonRight') { should eq ['S-1-0-0'] }
  end
end

control 'cis-act-as-os-2.2.3' do
  impact 0.7
  title '2.2.3 Set Act as part of the operating system to No One'
  desc 'Set Act as part of the operating system to No One'
  tag cis: ['windows_2012r2:2.2.3', 'windows_2016:2.2.3', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeTcbPrivilege') { should eq ['S-1-0-0'] }
  end
end

control 'cis-add-workstations-2.2.4' do
  impact 0.7
  title '2.2.4 Set Add workstations to domain to Administrators'
  desc 'Set Add workstations to domain to Administrators'
  tag cis: ['windows_2012r2:2.2.4', 'windows_2016:2.2.4', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeMachineAccountPrivilege') { should eq ['S-1-5-32-544'] }
  end
end

control 'cis-adjust-memory-quotas-2.2.5' do
  impact 0.7
  title '2.2.5 Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  desc 'Set Adust memory quotas for a process to Administrators, LOCAL SERVICE, NETWORK SERVICE'
  tag cis: ['windows_2012r2:2.2.5', 'windows_2016:2.2.5', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-19' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-20' }
    its('SeIncreaseQuotaPrivilege') { should include 'S-1-5-32-544' }
  end
end
