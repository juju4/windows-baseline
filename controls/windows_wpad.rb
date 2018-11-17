# frozen_string_literal: true

title 'Windows Web Proxy Auto-Discovery Protocol (WPAD)'

control 'wpad-101' do
  impact 1.0
  title 'WPAD mitigations'
  desc 'Ensure Web Proxy Auto-Discovery Protocol is disabled'
  ref url: 'https://it.slashdot.org/story/16/08/13/0149241/disable-wpad-now-or-have-your-accounts-compromised-researchers-warn'
  describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad') do
    it { should exist }
    its('WpadOverride') { should eq 1 }
  end
end
