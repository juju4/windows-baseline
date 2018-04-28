
title 'Password Policy'

control 'cis-enforce-password-history-1.1.1' do
  impact 0.7
  title '1.1.1 Set Enforce password history to 24 or more passwords'
  desc 'Set Enforce password history to 24 or more passwords'
  tag cis: ['windows_2012r2:1.1.1', 'windows_2016:1.1.1', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('PasswordHistorySize') { should be >= 24 }
  end
end

control 'cis-maximum-password-age-1.1.2' do
  impact 0.7
  title '1.1.2 Set Maximum password age to 60 or fewer days, but not 0'
  desc 'Set Maximum password age to 60 or fewer days, but not 0'
  tag cis: ['windows_2012r2:1.1.2', 'windows_2016:1.1.2', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('MaximumPasswordAge') { should be <= 60 }
    its('MaximumPasswordAge') { should be > 0 }
  end
end

control 'cis-minimum-password-age-1.1.3' do
  impact 0.7
  title '1.1.3 Set Minimum password age to 1 or more days'
  desc 'Set Minimum password age to 1 or more days'
  tag cis: ['windows_2012r2:1.1.3', 'windows_2016:1.1.3', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('MinimumPasswordAge') { should be >= 1 }
  end
end

control 'cis-minimum-password-length-1.1.4' do
  impact 0.7
  title '1.1.4 Set Minimum password length to 14 or more characters'
  desc 'Set Minimum password length to 14 or more characters'
  tag cis: ['windows_2012r2:1.1.4', 'windows_2016:1.1.4', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('MinimumPasswordLength') { should be >= 14 }
  end
end

control 'cis-password-complexity-1.1.6' do
  impact 0.7
  title '1.1.6 Set Store passwords using reversible encryption to Disabled'
  desc 'Set Store passwords using reversible encryption to Disabled'
  tag cis: ['windows_2012r2:1.1.6', 'windows_2016:1.1.6', 'level1']
  ref 'CIS Microsoft Windows Server 2012 R2 Benchmark v2.3.0'
  ref 'CIS Microsoft Windows Server 2016 RTM (Release 1607) Benchmark v1.0.0'
  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end
