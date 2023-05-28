# openwrt-setup
Scripts for automatic OpenWRT deployment and maintenance. At the time of writing the scripts nor the associated OpenWRT configuration have been tested adequately. 

At a high level, OpenWRT devices configured by this repo are "dumb" access points with VLANs on the wifi networks and ethernet switch. More specifically, the config from this repo makes the following major configuration changes:
* VLANs:
  * WAN port rejects untagged traffic, and tags outgoing traffic
  * LAN ports are all untagged on one of the VLANs
  * Each wifi network goes on a different VLAN
  * OpenWRT only has a IPv4 configuration for itself (via an upstream DHCP server) on the VLANs intended for admin access
  * Configuration based on: [OneMarcFifty, "VLANs in OpenWrt 21"](https://www.youtube.com/watch?v=qeuZqRqH-ug)
* Wifi:
  * Multiple separate 5 GHz wifi networks with 802.11r roaming enabled. Add another OpenWRT device with the same 5 GHz wifi configuration and you should see supported clients roaming when the signal strength becomes poor. Configuration based on:
    *  [OneMarcFifty, "CHEAP WI-FI MESH ALTERNATIVE with fast roaming OpenWrt Wi-Fi Access points"](https://www.youtube.com/watch?v=kMgs2XFClaM)
    * [Wireless Access Point / Dumb Access Point](https://openwrt.org/docs/guide-user/network/wifi/dumbap)
    *  [fabricio, "Wi-Fi roaming recipe"](https://forum.openwrt.org/t/wi-fi-roaming-recipe/70538/2)
  * Non-roaming 2.4 GHz wifi configuration, intended for clients that don't support robust wifi implementations (e.g., IOT devices)
* SSH: 
  * Password-based ssh access is disabled
  * The user's ~/.ssh/authorized_keys is copied to OpenWRT
* Unique wifi channels, SSIDs, and hostnames are assigned based on the OpenWRT board id and the first MAC address. Multiple OpenWRT devices with a similar configuration can be managed with minimal additional code
* NTP: Configured and local NTP servers are added
* wpad: Installs wpad-openssl (configurable) so 802.11k, 802.11v, 802.11w and WPA3 features are available

The following commonly used OpenWRT features have been disabled, which may be problematic for other use cases:
* DHCP and DNS server: An upstream router that provides these is expected to be used
* Firewall: The intent is that clients on different VLANs cannot communicate with each other unless allowed by an upstream managed switch or router. 
* The default LAN interface is removed (replaced by one interface per VLAN). The upstream managed switch/router (connected via the OpenWRT WAN port) needs to have VLANs configured.

## Files
* provision.sh
  * Sets up a freshly flashed OpenWRT system with factory defaults (ssh enabled, no root password, OpenWRT IP is 192.168.1.1)
* provision_secrets.sh
  * Contains setup for sensitive info like wifi passwords. Not included. Should be placed in a subfolder "SECRET" wrt provision.sh
* provision_secrets_censored_example.sh
  * A censored example of provision_secrets.sh. Create the SECRET subfolder, customize this file, move it into the SECRET subfolder, then rename it to provision_secrets.sh
