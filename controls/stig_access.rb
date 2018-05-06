
title 'Windows Access Configuration - STIG'

control 'windows-acl-100' do
  impact 1.0
  title 'Verify the Windows folder permissions are properly set'
  desc 'Ensure Windows folder is writable by Administrators but not Users'
  describe file('c:/windows') do
    it { should be_directory }
    ## FIXME! `check_file_permission_by_mask` is not supported on Windows
    # it { should be_writable.by('Administrator') }
    # it { should_not be_writable.by('Users') }
  end
  describe powershell('Get-Acl -Path "C:\windows" | fl') do
    its('stdout') { should include 'Owner  : NT SERVICE\TrustedInstaller' }
    its('stdout') { should include 'NT AUTHORITY\SYSTEM Allow  268435456' }
    its('stdout') { should include 'NT AUTHORITY\SYSTEM Allow  Modify, Synchronize' }
    its('stdout') { should include 'BUILTIN\Administrators Allow  268435456' }
    its('stdout') { should include 'BUILTIN\Administrators Allow  Modify, Synchronize' }
    its('stdout') { should include 'BUILTIN\Users Allow  -1610612736' }
    its('stdout') { should include 'BUILTIN\Users Allow  ReadAndExecute, Synchronize' }
    its('stdout') { should include 'NT SERVICE\TrustedInstaller Allow  268435456' }
    its('stdout') { should include 'NT SERVICE\TrustedInstaller Allow  FullControl' }
    its('stdout') { should include 'CREATOR OWNER Allow  268435456' }
  end
  describe command('icacls "c:\Windows"') do
    its('stdout') { should include 'NT AUTHORITY\SYSTEM:(M)' }
    its('stdout') { should include 'NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)' }
    its('stdout') { should include 'BUILTIN\Administrators:(M)' }
    its('stdout') { should include 'BUILTIN\Administrators:(OI)(CI)(IO)(F)' }
    its('stdout') { should include 'BUILTIN\Users:(RX)' }
    its('stdout') { should include 'BUILTIN\Users:(OI)(CI)(IO)(GR,GE)' }
    its('stdout') { should include 'CREATOR OWNER:(OI)(CI)(IO)(F)' }
  end
end

control 'windows-acl-101' do
  impact 1.0
  title 'Verify the C drive folder permissions are properly set'
  desc 'Changing the system\'s file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2016-11-03/finding/V-63373'
  describe file('c:') do
    it { should be_directory }
    ## FIXME! `check_file_permission_by_mask` is not supported on Windows
    # it { should be_writable.by('Administrator') }
    # it { should be_writable.by('SYSTEM') }
    # it { should_not be_writable.by('Users') }
  end
  describe command('icacls "c:\"') do
    # its('stdout') { should include 'NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)' }
    its('stdout') { should include 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' }
    its('stdout') { should include 'BUILTIN\Administrators:(OI)(CI)(F)' }
    its('stdout') { should include 'BUILTIN\Users:(OI)(CI)(RX)' }
    its('stdout') { should include 'BUILTIN\Users:(CI)(AD)' }
    its('stdout') { should include 'BUILTIN\Users:(CI)(IO)(WD)' }
    its('stdout') { should include 'CREATOR OWNER:(OI)(CI)(IO)(F)' }
  end
end

control 'windows-acl-200' do
  impact 1.0
  title 'Verify the registry permissions are properly set - HKLM'
  desc 'The registry is integral to the function, security, and stability of the Windows system. Changing the system\'s registry permissions allows the possibility of unauthorized and anonymous modification to the operating system.'
  ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63593'
  # describe registry_key('HKLM\Security') do
  #   it { should exist }
  #   it { should be_writable.by('Administrator') }
  #   it { should be_writable.by('SYSTEM') }
  #   it { should_not be_readable.by('Users') }
  #   it { should_not be_writable.by('Users') }
  # end
  # describe registry_key('HKLM\System') do
  #   it { should exist }
  #   it { should be_writable.by('Administrator') }
  #   it { should be_writable.by('SYSTEM') }
  #   it { should be_writable.by('CREATOR OWNER') }
  #   it { should be_readable.by('Users') }
  #   it { should_not be_writable.by('Users') }
  # end
  describe powershell('Get-Acl "HKLM:\System" | fl') do
    its('stdout') { should include 'NT AUTHORITY\SYSTEM Allow  FullControl' }
    its('stdout') { should include 'NT AUTHORITY\SYSTEM Allow  268435456' }
    its('stdout') { should include 'BUILTIN\Administrators Allow  FullControl' }
    its('stdout') { should include 'BUILTIN\Administrators Allow  268435456' }
    its('stdout') { should include 'BUILTIN\Users Allow  ReadKey' }
    its('stdout') { should include 'BUILTIN\Users Allow  -2147483648' }
    its('stdout') { should include 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey' }
  end
  # describe registry_key('HKLM\Software') do
  #   it { should exist }
  #   it { should be_writable.by('Administrator') }
  #   it { should be_writable.by('SYSTEM') }
  #   it { should be_writable.by('CREATOR OWNER') }
  #   it { should be_readable.by('Users') }
  #   it { should_not be_writable.by('Users') }
  # end
  describe powershell('Get-Acl "HKLM:\Software" | fl') do
    its('stdout') { should include 'BUILTIN\Administrators Allow  FullControl' }
    its('stdout') { should include 'BUILTIN\Users Allow  ReadKey' }
  end
end
