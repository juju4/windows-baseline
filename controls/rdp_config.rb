
title 'Windows RDP Configuration'

control 'windows-rdp-100' do
  impact 1.0
  title 'Windows Remote Desktop Configured to Always Prompt for Password'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  ref url: 'https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-3453'
  describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    its('fPromptForPassword') { should eq 1 }
  end
end

control 'windows-rdp-101' do
  impact 1.0
  title 'Strong Encryption for Windows Remote Desktop Required'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.'
  ref url: 'https://www.stigviewer.com/stig/windows_server_2012_2012_r2_member_server/2016-12-19/finding/V-3454'
  describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should exist }
    its('MinEncryptionLevel') { should eq 3 }
  end
end
