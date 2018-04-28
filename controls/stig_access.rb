
title 'Windows Access Configuration - STIG'
# TODO: go deeper? Get-Acl -Path ... | fl

control 'windows-acl-100' do
  impact 1.0
  title 'Verify the Windows folder permissions are properly set'
  describe file('c:/windows') do
    it { should be_directory }
    it { should be_writable.by('Administrator') }
    it { should_not be_writable.by('Users') }
  end
end

control 'windows-acl-101' do
  impact 1.0
  title 'Verify the C drive folder permissions are properly set'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-11-03/finding/V-63373'
  describe file('c:') do
    it { should be_directory }
    it { should be_writable.by('Administrator') }
    it { should be_writable.by('SYSTEM') }
    it { should_not be_writable.by('Users') }
  end
end

control 'windows-acl-200' do
  impact 1.0
  title 'Verify the registry permissions are properly set - HKLM'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63593'
  describe registry_key('HKLM\Security') do
    it { should exist }
    it { should be_writable.by('Administrator') }
    it { should be_writable.by('SYSTEM') }
    it { should_not be_readable.by('Users') }
    it { should_not be_writable.by('Users') }
  end
  describe registry_key('HKLM\System') do
    it { should exist }
    it { should be_writable.by('Administrator') }
    it { should be_writable.by('SYSTEM') }
    it { should be_writable.by('CREATOR OWNER') }
    it { should be_readable.by('Users') }
    it { should_not be_writable.by('Users') }
  end
  describe registry_key('HKLM\Software') do
    it { should exist }
    it { should be_writable.by('Administrator') }
    it { should be_writable.by('SYSTEM') }
    it { should be_writable.by('CREATOR OWNER') }
    it { should be_readable.by('Users') }
    it { should_not be_writable.by('Users') }
  end
end
