# DeviantZero
SentinelOne killer without requiring safe mode

If SentinelOne has been installed with tamper protection, it is impossible to uninstall the agent without the passphrase, which is only retrievable in the SentinelOne web console.

There is an exception, where you can use SentinelCleaner provided by SentinelOne in Safe Mode to uninstall without using a passphrase.

SentinelOne sets the file permissions so only it's NT Service account can modify. SYSTEM, Admins & Users only have access to read and execute.
So, if we impersonate SentinelOne's token (being S-1-5-80-2740271751-1964628467-255359229-3809823433-2765370874) we will be able to modify registry keys and files.

This POC only removes the detection, firewall and response toolkit for S1. It does not remove the ELAM (Early-Launch Anti-Malware) driver nor the DeviceControl driver, since those are kernel drivers and if tampered with it will cause the system to be unbootable.

The scanning and firewall are done by a file system driver called SentinelMonitor. Unloading this driver will remove SentinelOne's ability to scan files and disable the firewall. This POC launches a command prompt using SentinelOne's Identifier and prevents the following services:

SentinelAgent (watchdog/response)
SentinelHelperService (Helper service)
SentinelStaticEngine (Static file scanner)
LogProcessorService (Creates logs of scans and submits to the SentinelOne dashboard)
SentinelMonitor (Monitor applications, firewall, etc, only most important one)

This is possible by setting the registry start key in HKLM\System\CurrentControlSet\Services\SERVICE to 4 (decimal), which represents it to be disabled and not to start.
Currrently, the file is undetected, however a few sentinelone installations I have obsereved had blocked this. Feel free to crypt it.

Credits to https://github.com/benheise for creating https://github.com/benheise/TrustedInstallerToken which this project was based off of.
