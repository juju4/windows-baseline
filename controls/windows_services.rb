
windows_services_harden = attribute('windows_services_harden', default: true, description: 'Should we ensure services hardening')
windows_services_list = attribute(
  'windows_services_list',
  default: %w[
    iphlpsvc
    lldtsvc
    NcaSvc
    SSDPSRV
    upnphost
    W3SVC
    WinHttpAutoProxySvc
    Xbox
  ],
  description: 'List of services to ensure are not running'
)

if windows_services_harden
  title 'Microsoft Windows services hardening'

  control 'services-1' do
    impact 0.7
    title 'Services to be disabled'
    desc 'Ensure non-relevant services are disabled'
    windows_services_list.each do |svc|
      describe service(svc.to_s) do
        it { should_not be_running }
      end
    end
  end
end
