# frozen_string_literal: true

windows_suspicous_fileassoc_hkcu_check = attribute('windows_suspicous_fileassoc_hkcu_check', default: true, description: 'Should we ensure file assoc changes for current user (HKCU)')
windows_suspicous_fileassoc_hkcr_check = attribute('windows_suspicous_fileassoc_hkcr_check', default: true, description: 'Should we ensure file assoc changes for classes root (HKCR)')

windows_suspicous_fileassoc = %w[
  HKCR\htafile\shell\open\command
  HKCR\VBSFile\shell\edit\command
  HKCR\VBSFile\shell\open\command
  HKCR\VBSFile\shell\open2\command
  HKCR\VBEFile\shell\edit\command
  HKCR\VBEFile\shell\open\command
  HKCR\VBEFile\shell\open2\command
  HKCR\JSFile\shell\open\command
  HKCR\JSEFile\shell\open\command
  HKCR\wshfile\shell\open\command
  HKCR\scriptletfile\shell\open\command
]

title 'Windows Suspicious extensions'

if windows_suspicous_fileassoc_hkcu_check
  control 'fileassoc-101' do
    impact 1.0
    title 'Review potentially dangerous extensions association - HKCU'
    ref url: 'https://bluesoul.me/2016/05/12/use-gpo-to-change-the-default-behavior-of-potentially-malicious-file-extensions/'
    describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.hta') do
      it { should exist }
      its('(Default)') { should eq '%windir%\system32\notepad.exe' }
    end
    describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbs') do
      it { should exist }
      its('(Default)') { should eq '%windir%\system32\notepad.exe' }
    end
    describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.VBE') do
      it { should exist }
      its('(Default)') { should eq '%windir%\system32\notepad.exe' }
    end
    describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.js') do
      it { should exist }
      its('(Default)') { should eq '%windir%\system32\notepad.exe' }
    end
    describe registry_key('HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pif') do
      it { should exist }
      its('(Default)') { should eq '%windir%\system32\notepad.exe' }
    end
  end
end

if windows_suspicous_fileassoc_hkcr_check
  control 'fileassoc-102' do
    impact 1.0
    title 'Review potentially dangerous extensions association - HKCR'
    ref url: 'https://bluesoul.me/2016/05/12/use-gpo-to-change-the-default-behavior-of-potentially-malicious-file-extensions/'
    windows_suspicous_fileassoc.each do |fileassoc|
      describe registry_key(fileassoc.to_s) do
        it { should exist }
        its('(Default)') { should eq '"%windir%\system32\notepad.exe" "%1"' }
      end
    end
  end
end
