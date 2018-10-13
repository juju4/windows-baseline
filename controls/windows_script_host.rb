
title 'Windows Script Host (WSH)'

control 'wsh-101' do
  impact 1.0
  title 'Windows Script Host mitigations'
  desc 'Ensure wscript is disabled'
  ref url: 'https://technet.microsoft.com/en-ca/library/ee198684.aspx'
  ref url: 'https://labsblog.f-secure.com/2016/04/19/how-to-disable-windows-script-host/'
  ref url: 'https://isc.sans.edu/forums/diary/Controlling+JavaScript+Malware+Before+it+Runs/21171/'
  describe registry_key('HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings') do
    it { should exist }
    its('Enabled') { should eq 0 }
    its('IgnoreUserSettings') { should eq 1 }
  end
end
