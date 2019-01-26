# frozen_string_literal: true

windows_stig = attribute('windows_stig', default: true, description: 'Should we check STIG controls')
windows_defaultpassword = attribute('windows_defaultpassword', default: true, description: 'Should we check that defaultpassword is not enabled - not valid for CI like Appveyor')
windows_deviceguard = attribute('windows_deviceguard', default: true, description: 'Should we check that Deviceguard is enabled - not valid for VM')

if windows_stig
  title 'STIG'

  control 'V-63375' do
    impact 1.0
    title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
    desc 'Storage of administrative credentials could allow unauthorized access. Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63375'
    describe registry_key('HKLM\Software\Policies\Microsoft\Windows\WinRM\Service') do
      it { should exist }
      its('DisableRunAs') { should eq 1 }
    end
  end

  control 'V-63545' do
    impact 1.0
    title 'Camera access from the lock screen must be disabled.'
    desc 'Enabling camera access from the lock screen could allow for unauthorized use. Requiring logon will ensure the device is only used by authorized personnel.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63545'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
      it { should exist }
      its('NoLockScreenCamera') { should eq 1 }
    end
  end

  control 'V-63549' do
    impact 1.0
    title 'The display of slide shows on the lock screen must be disabled.'
    desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel. Turning off this feature will limit access to the information to a logged on user.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63549'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization') do
      it { should exist }
      its('NoLockScreenSlideshow') { should eq 1 }
    end
  end

  if windows_defaultpassword
    control 'V-63551' do
      impact 1.0
      title 'Automatic logons must be disabled.'
      desc 'Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer. Automatic logon with administrator privileges would give full access to an unauthorized individual.'
      ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63551'
      describe registry_key('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
        it { should exist }
        its('DefaultPassword') { should eq '' }
      end
    end
  end

  control 'V-63555' do
    impact 1.0
    title 'IPv6 source routing must be configured to highest protection.'
    desc 'Configuring the system to disable IPv6 source routing protects against spoofing.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63555'
    describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters') do
      it { should exist }
      its('DisableIpSourceRouting') { should eq 2 }
    end
  end

  control 'V-63657' do
    impact 1.0
    title 'Unauthenticated RPC clients must be restricted from connecting to the RPC server.'
    desc 'Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent anonymous connections.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63657'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
      it { should exist }
      its('RestrictRemoteClients') { should eq 1 }
    end
  end

  control 'V-63545' do
    impact 1.0
    title 'The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.'
    desc ''
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63563'
    describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') do
      it { should exist }
      its('EnableICMPRedirect') { should eq 0 }
    end
  end

  control 'V-63567' do
    impact 1.0
    title 'The system must be configured to ignore NetBIOS name release requests except from WINS servers.'
    desc ''
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63567'
    describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters') do
      it { should exist }
      its('NoNameReleaseOnDemand') { should eq 1 }
    end
  end

  control 'V-63545' do
    impact 1.0
    title 'Insecure logons to an SMB server must be disabled.'
    desc 'Insecure guest logons allow unauthenticated access to shared folders. Shared resources on a system must require authentication to establish proper access.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63569'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
      it { should exist }
      its('AllowInsecureGuestAuth') { should eq 0 }
    end
  end

  control 'V-63591' do
    impact 1.0
    title 'Wi-Fi Sense must be disabled.'
    desc 'Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared. It also allows the sharing of the system\'s known networks to contacts. Automatically connecting to hotspots and shared networks can expose a system to unsecured or potentially malicious systems.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63591'
    describe registry_key('HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config') do
      it { should exist }
      its('AutoConnectAllowedOEM') { should eq 0 }
    end
  end

  if windows_deviceguard
    control 'V-63599' do
      impact 1.0
      title 'Credential Guard must be running on domain-joined systems.'
      desc 'Credential Guard uses virtualization based security to protect secrets that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.'
      ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63599'
      describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
        it { should exist }
        its('LsaCfgFlags') { should eq 1 }
      end
    end

    control 'V-63603' do
      impact 1.0
      title 'Virtualization-based protection of code integrity must be enabled on domain-joined systems.'
      desc 'Virtualization based protection of code integrity enforces kernel mode memory protections as well as protecting Code Integrity validation paths. This isolates the processes from the rest of the operating system and can only be accessed by privileged system software.'
      ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63603'
      describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
        it { should exist }
        its('HypervisorEnforcedCodeIntegrity') { should eq 1 }
      end
    end
  end

  control 'V-63615' do
    impact 1.0
    title 'Downloading print driver packages over HTTP must be prevented.'
    desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting prevents the computer from downloading print driver packages over HTTP.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63615'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
      it { should exist }
      its('DisableWebPnPDownload') { should eq 1 }
    end
  end

  control 'V-63621' do
    impact 1.0
    title 'Web publishing and online ordering wizards must be prevented from downloading a list of providers.'
    desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting prevents Windows from downloading a list of providers for the Web publishing and online ordering wizards.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63621'
    describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
      it { should exist }
      its('NoWebServices') { should eq 1 }
    end
  end

  control 'V-63623' do
    impact 1.0
    title 'Printing over HTTP must be prevented.'
    desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63623'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
      it { should exist }
      its('DisableHTTPPrinting') { should eq 1 }
    end
  end

  control 'V-63629' do
    impact 1.0
    title 'The network selection user interface (UI) must not be displayed on the logon screen.'
    desc 'Enabling interaction with the network selection UI allows users to change connections to available networks without signing into Windows.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63629'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\System') do
      it { should exist }
      its('DontDisplayNetworkSelectionUI') { should eq 1 }
    end
  end

  control 'V-63633' do
    impact 1.0
    title 'Local users on domain-joined computers must not be enumerated.'
    desc 'The username is one part of logon credentials that could be used to gain access to a system. Preventing the enumeration of users limits this information to authorized personnel.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63633'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\System') do
      it { should exist }
      its('EnumerateLocalUsers') { should eq 0 }
    end
  end

  control 'V-63645' do
    impact 1.0
    title 'Users must be prompted for a password on resume from sleep (on battery).'
    desc 'Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (on battery).'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63645'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
      it { should exist }
      its('DCSettingIndex') { should eq 1 }
    end
  end

  control 'V-63669' do
    impact 1.0
    title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
    desc ''
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63669'
    describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
      it { should exist }
      its('InactivityTimeoutSecs') { should eq 900 }
    end
  end

  control 'V-63679' do
    impact 1.0
    title 'Administrator accounts must not be enumerated during elevation.'
    desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user. This setting configures the system to always require users to type in a username and password to elevate a running application.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63679'
    describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
      it { should exist }
      its('EnumerateAdministrators') { should eq 0 }
    end
  end

  control 'V-63683' do
    impact 1.0
    title 'Windows Telemetry must be configured to the lowest level of data sent to Microsoft.'
    desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Limiting this capability will prevent potentially sensitive information from being sent outside the enterprise.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-08/finding/V-63683'
    describe registry_key('HKLM\Software\Policies\Microsoft\Windows\DataCollection') do
      it { should exist }
      its('AllowTelemetry') { should eq 1 }
    end
  end

  control 'V-63701' do
    impact 1.0
    title 'Users must not be allowed to ignore SmartScreen filter warnings for unverified files in Microsoft Edge.'
    desc 'The SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites and file downloads. If users are allowed to ignore warnings from the SmartScreen filter they could still download potentially malicious files.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63701'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter') do
      it { should exist }
      its('PreventOverrideAppRepUnknown') { should eq 1 }
    end
  end

  control 'V-63699' do
    impact 1.0
    title 'Users must not be allowed to ignore SmartScreen filter warnings for malicious websites in Microsoft Edge.'
    desc 'The SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites and file downloads. If users are allowed to ignore warnings from the SmartScreen filter they could still access malicious websites.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-02-21/finding/V-63699'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter') do
      it { should exist }
      its('PreventOverride') { should eq 1 }
    end
  end

  control 'V-63677' do
    impact 1.0
    title 'Enhanced anti-spoofing when available must be enabled for facial recognition.'
    desc 'Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support it.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-11-03/finding/V-63677'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures') do
      it { should exist }
      its('EnhancedAntiSpoofing') { should eq 1 }
    end
  end

  control 'V-63663' do
    impact 1.0
    title 'The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'
    desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63663'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat') do
      it { should exist }
      its('DisableInventory') { should eq 1 }
    end
  end

  control 'V-63545' do
    impact 1.0
    title 'The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.'
    desc 'Control of credentials and the system must be maintained within the enterprise. Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-12-01/finding/V-63659'
    describe registry_key('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
      it { should exist }
      its('MSAOptional') { should eq 1 }
    end
  end

  control 'V-63721' do
    impact 1.0
    title 'The minimum pin length for Microsoft Passport for Work must be 6 characters or greater.'
    desc 'Microsoft Passport for Work allows the use of PINs as well as biometrics for authentication without the sending a password to a network or website where it could be compromised. Longer minimum PIN lengths increase the available combinations an attacker would have to attempt. Shorter minimum length significantly reduces the strength.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63721'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity') do
      it { should exist }
      its('MinimumPINLength') { should >= 6 }
    end
  end

  control 'V-63717' do
    impact 1.0
    title 'The use of a hardware security device with Windows Hello for Business must be enabled.'
    desc 'The use of a Trusted Platform Module (TPM) to store keys for Windows Hello for Business provides additional security. Keys stored in the TPM may only be used on that system while keys stored using software are more susceptible to compromise and could be used on other systems.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-11-03/finding/V-63717'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\PassportForWork') do
      it { should exist }
      its('RequireSecurityDevice') { should eq 1 }
    end
  end

  control 'V-63705' do
    impact 1.0
    title 'InPrivate browsing in Microsoft Edge must be disabled.'
    desc 'The InPrivate browsing feature in Microsoft Edge prevents the storing of history, cookies, temporary Internet files, or other data. Disabling this feature maintains this data for review as necessary.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63705'
    describe registry_key('HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main') do
      it { should exist }
      its('AllowInPrivate') { should eq 0 }
    end
  end

  control 'V-63731' do
    impact 1.0
    title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.'
    desc 'Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63731'
    describe registry_key('HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services') do
      it { should exist }
      its('fDisableCdm') { should eq 1 }
    end
  end

  control 'V-63763' do
    impact 1.0
    title 'The Windows SMB client must be configured to always perform SMB packet signing.'
    desc 'The server message block (SMB) protocol provides the basis for many network operations. Digitally signed SMB packets aid in preventing man-in-the-middle attacks. If this policy is enabled, the SMB client will only communicate with an SMB server that performs SMB packet signing.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63703'
    describe registry_key('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
      it { should exist }
      its('RequireSecuritySignature') { should eq 1 }
    end
  end

  control 'V-63763' do
    impact 1.0
    title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'
    desc 'Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously vs. using the computer identity.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63763'
    describe registry_key('HKLM\System\CurrentControlSet\Control\LSA') do
      it { should exist }
      its('UseMachineId') { should eq 1 }
    end
  end

  control 'V-63765' do
    impact 1.0
    title 'NTLM must be prevented from falling back to a Null session.'
    desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-10-28/finding/V-63765'
    describe registry_key('HKLM\System\CurrentControlSet\Control\LSA\MSV1_0') do
      it { should exist }
      its('allownullsessionfallback') { should eq 0 }
    end
  end

  control 'V-63767' do
    impact 1.0
    title 'PKU2U authentication using online identities must be prevented.'
    desc 'PKU2U is a peer-to-peer authentication protocol. This setting prevents online identities from authenticating to domain-joined systems. Authentication will be centrally managed with Windows user accounts.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-10-28/finding/V-63767'
    describe registry_key('HKLM\System\CurrentControlSet\Control\LSA\pku2u') do
      it { should exist }
      its('AllowOnlineID') { should eq 0 }
    end
  end

  control 'V-63795' do
    impact 1.0
    title 'Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.'
    desc 'Certain encryption types are no longer considered secure. This setting configures a minimum encryption type for Kerberos, preventing the use of the DES and RC4 encryption suites.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2015-11-30/finding/V-63795'
    ref url: 'https://blogs.technet.microsoft.com/petergu/2013/04/14/interpreting-the-supportedencryptiontypes-registry-key/'
    describe registry_key('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
      it { should exist }
      its('SupportedEncryptionTypes') { should >= 2_147_483_640 }
    end
  end

  control 'V-63803' do
    impact 1.0
    title 'The system must be configured to the required LDAP client signing level.'
    desc 'This setting controls the signing requirements for LDAP clients. This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63803'
    describe registry_key('HKLM\System\CurrentControlSet\Services\LDAP') do
      it { should exist }
      its('LDAPClientIntegrity') { should eq 1 }
    end
  end

  control 'V-63577' do
    impact 1.0
    title 'Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares'
    desc 'Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in Hardened UNC paths before allowing access them. This aids in preventing tampering with or spoofing of connections to these paths.'
    ref url: 'https://www.stigviewer.com/stig/windows_10/2016-06-24/finding/V-63577'
    ref 'CIS L1 18.4.14.1'
    describe registry_key('HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths') do
      it { should exist }
      its('\\\\*\NETLOGON') { should eq 'RequireMutualAuthentication=1,RequireIntegrity=1' }
      its('\\\\*\SYSVOL') { should eq 'RequireMutualAuthentication=1,RequireIntegrity=1' }
    end
  end

end
