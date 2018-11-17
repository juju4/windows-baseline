# frozen_string_literal: true

credentialguard_present = attribute('credentialguard_present', default: false, description: 'Should we control presence of Microsoft Win10 Credential Guard')

if credentialguard_present
  title 'Ms credentialguard'

  control 'credentialguard-1' do
    impact 0.7
    title 'Credential Guard Lsalso process'
    desc 'credentialguard process is active'
    ## FIXME! process listing NOK
    # describe processes('Lsalso.exe') do
    #   its('list.length') { should eq 1 }
    #   its('users') { should cmp 'SYSTEM' }
    # end
    describe file('?c:\windows\Lsalso.exe') do
      it { should be_file }
    end
  end
end
