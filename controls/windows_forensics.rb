
title 'Forensics support'

control 'forensics-101' do
  impact 1.0
  title 'Ensure Ntfs LastAccessUpdate is enabled'
  desc 'Ensure Ntfs LastAccessUpdate is recorded'
  ref url: 'https://technet.microsoft.com/en-us/library/cc959914.aspx'
  describe registry_key('HKLM\SYSTEM\CurrentControlSet\Control\FileSystem') do
    it { should exist }
    its('NtfsDisableLastAccessUpdate') { should eq 0 }
  end
end
control 'forensics-102' do
  impact 1.0
  title 'Ensure Superfetch is enabled'
  desc 'Ensure Prefetch and Superfetch functions are enabled'
  ref url: 'http://resources.infosecinstitute.com/windows-systems-artifacts-digital-forensics-part-iii-prefetch-files/'
  ref url: 'http://www.forensicswiki.org/wiki/Prefetch'
  describe registry_key('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters') do
    it { should exist }
    its('EnablePrefetcher') { should eq 3 }
    its('EnableSuperfetch') { should eq 3 }
  end
end
