# frozen_string_literal: true

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

control 'fileassoc-101' do
  impact 1.0
  title 'Review potentially dangerous extensions association'
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

  windows_suspicous_fileassoc.each do |fileassoc|
    describe registry_key(fileassoc.to_s) do
      it { should exist }
      its('(Default)') { should eq '"%windir%\system32\notepad.exe" "%1"' }
    end
  end
end
