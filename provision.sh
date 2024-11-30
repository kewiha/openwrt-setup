#!/bin/bash -e
#Usage: run as only once on a system with factory defaults. Running on a partially configured system may cause issues.
	#No need to run as root
	#Run on a user with ~/.ssh/authorized_keys populated
#Physical setup:
	#Flash openwrt board with the latest openwrt firmware. Reset to factory defaults
	#Connect computer to LAN port of openwrt board
	#Connect openwrt WAN port to a working router that will assign it an ip address, give it dns, and let it run opkg update & install
		#Double NAT should not be problematic as long as the router attached to WAN isn't also using 192.168.1.0/24
#Notes:
	#This script modifies your ~/.ssh/known_hosts file
	#Can be run on a windows OS via WSL2 as long as the WSL2 VM can reach 192.168.1.1 via ssh

########################################################################
printf '%s\n' "### Clearing 192.168.1.1 from ~/.ssh/authorized_keys ###"
########################################################################
ssh-keygen -f ~/.ssh/known_hosts -R "192.168.1.1"

#################################################
printf '%s\n' "### Get board_id and firstMAC ###"
#################################################
board_id="$(sshpass -p "" ssh -o StrictHostKeyChecking=no -T root@192.168.1.1 grep '\"id\":\ ' /etc/board.json | sed 's;\"\,.*;;' | sed 's;.*\";;')"
firstMAC="$(sshpass -p "" ssh -T root@192.168.1.1 ip addr show | grep link/ether | head -n 1 | awk '{print $2}' | sha256sum)"
	#Stored and compared as sha256sum

if [[ "$board_id" == "" || "$firstMAC" == "" ]] ; then
	printf '%s\n' "ERROR in provision.sh: Was not able to get board_id and/or firstMAC via ssh"
	printf '%s\n' "board_id: $board_id"
	printf '%s\n' "firstMAC: $firstMAC"
	exit 1
fi

###############################################################
printf '%s\n' "### Decide which deployment settings to use ###"
###############################################################
if [[ ("$board_id" == "dlink,dir-1935-a1" && "$firstMAC" == "2f2d078888c469b9fd22500225f65b2825c09d143e5958e170401993885bc800  -") \
   || ("$board_id" == "dlink,dir-867-a1"  && "$firstMAC" == "f6168da64f313b5a63f3c23b67ac56f2f202d258758deee5d82abc3ac35b60b1  -") \
   || ("$board_id" == "dlink,dir-882-a1"  && "$firstMAC" == "cc6d054aaf40b90e75c64ae18159c2784c5c27c526e58289dc1018f7585d7d33  -") \
   || ("$board_id" == "dlink,dir-1960-a1" && "$firstMAC" == "031aa1796dda3ad330512accf740f47fdca32ab07750fce551fecef3bfb7e0cb  -") ]] ; then
	### Hardware Notes ###
	#WAN port on same interface as LAN
	#First radio is 2.4 GHz, 2nd is 5 GHz

	### Config Notes ###
	#WAN port is uplink
	#Hard-coded wifi channels
	#Wifi roaming enabled (but not necessarily configured optimally)

	deployment="home.lan"
elif [[ ("$board_id" == "tplink,archer-c7-v4" && "$firstMAC" == "01acfe236ec608972388544e25a83e3c468785c4ea810257f2c04f7d89755195  -") \
     || ("$board_id" == "tplink,archer-c7-v2" && "$firstMAC" == "d4eecffb3168c08a373179566f6a42d524ecc67c21593428a9f0a8ff17a7b093  -") ]] ; then
	### Hardware Notes ###
	#WAN port on separate interface
	#First radio is 5 GHz, 2nd is 2.4 GHz

	### Config Notes ###
	#WAN port non functional when configured. Connect uplink to LAN port
	#Wifi channels set to auto
	#Wifi roaming disabled

	deployment="rob.lan"
	#deployment="rob.lan.noroam"
else
        printf '%s\n' "ERROR in provision.sh: board_id and firstMAC combination are unknown. Configure script for your board & settings before running."
        exit 1
fi

if [[ "$deployment" == "" ]]; then
        printf '%s\n' "ERROR: deployment is blank (outside of openwrt ssh session)"
        exit 1
fi

##########################################################
printf '%s\n' "### Check/install desired version wpad if needed ###"
if [[ "$deployment" == "home.lan" || "$deployment" == "rob.lan" ]]; then
	sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	wpad_package="wpad-openssl"
	wpad_installed="$(opkg list-installed | grep wpad | awk '{print $1}')"
	if [[ "$(printf '%s\n' "$wpad_installed" | wc -l )" != "1" ]] ; then
		printf '%s\n' "ERROR in provision.sh: Multiple wpad packages installed. Unclear which to remove"
		exit 1
	elif [[ "$(printf '%s\n' "$wpad_installed" | grep "$wpad_package" | wc -l )" != "1" ]] ; then
	        printf '%s\n' "Removing $wpad_installed"
		opkg update && opkg remove "$wpad_installed" && opkg install wpad-openssl && reboot
	fi
EOI
	#Do not indent EOI. Causes issues.
	sleep 60 #Increase if router doesn't come back online fast enough
else
	printf '%s\n' "Skipping due to deployment=$deployment"
fi

###################################################
printf '%s\n' "### First big batch of commands ###"
###################################################
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI

	#FIX LATER
        deployment="rob.lan"

if [[ "$deployment" == "" ]]; then
	printf '%s\n' "ERROR: deployment is blank (inside openwrt ssh session)"
	exit 1
fi

################################
printf '%s\n' "#Getting board id"
board_id="$(grep "\"id\":\ " /etc/board.json | sed 's;\"\,.*;;' | sed 's;.*\";;')"
if [[ "$(printf '%s\n' $board_id | wc -l)" != "1" ]] ; then
	printf '%s\n' "ERROR in provision.sh: Failed to get board id from /etc/board.json"
	exit 1
fi
case "$board_id" in
	"dlink,dir-1935-a1")
		board_tested=true
		;;
	"dlink,dir-867-a1")
		board_tested=true
		;;
        "dlink,dir-882-a1")
                board_tested=true
                ;;
	"dlink,dir-1960-a1")
                board_tested=true
                ;;
        "tplink,archer-c7-v2")
                board_tested=true
                ;;
        "tplink,archer-c7-v4")
                board_tested=true
                ;;
	*)
		board_tested=false
		;;
esac
if [[ "$board_tested" != "true" ]] ; then
	printf '%s\n' "ERROR in provision.sh: Board id from /etc/board.json does not match tested_board_ids. Need to customize provision...sh to support this board first"
	exit 1
fi

######################################
printf '%s\n' "#Generic non-uci config"
if [[ -f /etc/sysctl.conf ]] ; then
        if [[ "$(cat /etc/sysctl.conf | sed 's;.*\#.*;;' | grep -v -e '^$' | wc -l)" != "0" ]] ; then
                printf '%s\n' "WARN: non-comment lines in sysctl.conf should not exist on a fresh install. Overwriting it"
        fi
fi
printf '%s\n' "net.ipv4.ip_forward=0" > /etc/sysctl.conf
        #Blocking ipv4 forwarding may improve security if it is not needed
printf '%s\n' "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.conf
        #ipv6 lines may perform similar function as net.ipv4.ip_forward=0, but this hasn't been confirmed nor tested
printf '%s\n' "net.ipv6.conf.default.forwarding=0" >> /etc/sysctl.conf
        #ipv6 lines may perform similar function as net.ipv4.ip_forward=0, but this hasn't been confirmed nor tested

/etc/init.d/firewall disable
/etc/init.d/dnsmasq disable
/etc/init.d/odhcpd disable
	#no firewall, DHCP (IPv4 or IPv6) or DNS server is used by this config
	#Remove the 3 lines above and configure the packages above if using openWRT as a router.
		#Other changes will probably be needed and aren't detailed.

#########################################
printf '%s\n' "#Generic uci system config"
uci revert system

#Time
uci set system.@system[0].zonename='America/Toronto'
uci set system.@system[0].timezone='EST5EDT,M3.2.0,M11.1.0'
if [[ "$deployment" == "home.lan" ]]; then
	#Custom NTP server list (defaults should be ok, these changes are optional)
	uci del system.ntp.enabled
	uci del system.ntp.enable_server
	uci add_list system.ntp.server='10.0.0.1'
        uci add_list system.ntp.server='10.1.0.1'
        uci add_list system.ntp.server='10.2.0.1'
fi

##########################################
printf '%s\n' "#Generic uci network config"
uci revert network

#This block reassigns the wan port to the main/LAN bridge.
#Probably only works on boards where WAN and LAN ports are on the same physical interface.
if [[ "$(uci show | grep '^network.wan6.*')" != "" ]] ; then
        uci delete network.wan6
fi
if [[ "$(uci show | grep '^network.wan.*')" != "" ]] ; then
	uci delete network.wan
fi
if [[ "$deployment" == "home.lan" ]]; then
	if [[ "$(uci show | grep "network.\@device\[0\].ports" | grep wan)" == "" ]] ; then
		uci add_list network.@device[0].ports='wan'
	fi
fi

printf '%s\n' "about to do a thing $deployment"
if [[ "$deployment" == "home.lan" ]]; then
        printf '%s\n' "$deployment: editing LAN proto et al"
	#This block creates VLAN bridges and assigns them to WAN/LAN ports
		#WAN: untagged for VLAN 1, tagged for the rest
		#LAN: untagged for VLAN 400
	uci add network bridge-vlan >> /dev/null
	uci set network.@bridge-vlan[-1].device='br-lan'
	uci set network.@bridge-vlan[-1].vlan='1'
	uci add_list network.@bridge-vlan[-1].ports='wan:u*'

	uci add network bridge-vlan >> /dev/null
	uci set network.@bridge-vlan[-1].device='br-lan'
	uci set network.@bridge-vlan[-1].vlan='100'
	uci add_list network.@bridge-vlan[-1].ports='wan:t'

	uci add network bridge-vlan >> /dev/null
	uci set network.@bridge-vlan[-1].device='br-lan'
	uci set network.@bridge-vlan[-1].vlan='200'
	uci add_list network.@bridge-vlan[-1].ports='wan:t'

	uci add network bridge-vlan >> /dev/null
	uci set network.@bridge-vlan[-1].device='br-lan'
	uci set network.@bridge-vlan[-1].vlan='300'
	uci add_list network.@bridge-vlan[-1].ports='wan:t'

	uci add network bridge-vlan >> /dev/null
	uci set network.@bridge-vlan[-1].device='br-lan'
	uci set network.@bridge-vlan[-1].vlan='400'
	uci add_list network.@bridge-vlan[-1].ports='lan1:u*'
	uci add_list network.@bridge-vlan[-1].ports='lan2:u*'
	uci add_list network.@bridge-vlan[-1].ports='lan3:u*'
	uci add_list network.@bridge-vlan[-1].ports='lan4:u*'
	uci add_list network.@bridge-vlan[-1].ports='wan:t'

	#This block creates networks on the bridges, makes openwrt request an ip addr on VLAN1
	uci set network.LAN=interface
	uci set network.LAN.proto='dhcp'
	uci set network.LAN.device='br-lan.1'
	uci set network.LAN.delegate='0'
	uci set network.KLAN=interface
	uci set network.KLAN.proto='none'
	uci set network.KLAN.device='br-lan.100'
	uci set network.KLAN.delegate='0'
	uci set network.KWLAN=interface
	uci set network.KWLAN.proto='none'
	uci set network.KWLAN.device='br-lan.200'
	uci set network.KWLAN.delegate='0'
	uci set network.IOT=interface
	uci set network.IOT.proto='none'
	uci set network.IOT.device='br-lan.300'
	uci set network.MLAN=interface
	uci set network.MLAN.proto='none'
	uci set network.MLAN.device='br-lan.400'
	uci del network.lan
elif [[ "$deployment" == "rob.lan" || "$deployment" == "rob.lan.noroam" ]]; then
	printf '%s\n' "$deployment: editing LAN proto et al"
	uci del dhcp.lan.ra_slaac
	uci del dhcp.lan.ra
	uci del dhcp.lan.ra_flags
	uci del dhcp.lan.dhcpv6
	uci del network.lan.ipaddr
	uci del network.lan.netmask
	uci del network.lan.ip6assign
	uci set network.lan.proto='dhcp'
fi

#######################################
printf '%s\n' "#Wireless Radio Settings"
uci revert wireless
uci set wireless.radio0.channel='auto' #May be overriden later
uci set wireless.radio1.channel='auto' #May be overriden later
uci set wireless.radio0.country='CA'
uci set wireless.radio1.country='CA'

#Cell coverage density: higher value = higher minimum data rates, lower compatibility
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.radio0.htmode='HT20'

	uci set wireless.radio1.htmode='VHT40'

	uci set wireless.radio0.cell_density='0'
	uci set wireless.radio1.cell_density='3'
elif [[ "$deployment" == "rob.lan" || "$deployment" == "rob.lan.noroam" ]]; then
	uci set wireless.radio0.htmode='VHT40'
	uci set wireless.radio1.htmode='HT20'

	uci set wireless.radio0.cell_density='3'
	uci set wireless.radio1.cell_density='3'
fi

#####################################
printf '%s\n' "#Wifi Network Settings"
#Create new wifi network(s) if needed
if [[ "$deployment" == "home.lan" ]]; then
        uci set wireless.wifinet2=wifi-iface
        uci set wireless.wifinet2.device='radio1'
        uci set wireless.wifinet2.mode='ap'
fi

#Interface attached to wifi network
if [[ "$deployment" == "home.lan" ]]; then
        uci set wireless.default_radio0.network='IOT'
        uci set wireless.default_radio1.network='LAN'
        uci set wireless.wifinet2.network='MLAN'
fi

#SSID
uci set wireless.default_radio0.ssid='PLACEHOLDER'
uci set wireless.default_radio1.ssid='PLACEHOLDER'
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.wifinet2.ssid='PLACEHOLDER'
fi

#Wifi password
uci set wireless.default_radio0.key='PLACEHOLDER'
uci set wireless.default_radio1.key='PLACEHOLDER'
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.wifinet2.key='PLACEHOLDER'
fi

#Wifi Crypto
uci set wireless.default_radio0.encryption='psk2+ccmp'
uci set wireless.default_radio1.encryption='psk2+ccmp'
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.wifinet2.encryption='psk2+ccmp'
fi

#802.11v Wifi Time Advertisement
uci set wireless.default_radio0.time_advertisement='2'
uci set wireless.default_radio1.time_advertisement='2'
uci set wireless.default_radio0.time_zone='EST5EDT,M3.2.0,M11.1.0'
uci set wireless.default_radio1.time_zone='EST5EDT,M3.2.0,M11.1.0'
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.wifinet2.time_advertisement='2'
	uci set wireless.wifinet2.time_zone='EST5EDT,M3.2.0,M11.1.0'
fi

#DTIM period
if [[ "$deployment" == "home.lan" ]]; then
        uci set wireless.default_radio0.dtim_period='1'
elif [[ "$deployment" == "rob.lan" || "$deployment" == "rob.lan.noroam" ]]; then
        uci set wireless.default_radio0.dtim_period='3'
fi
uci set wireless.default_radio1.dtim_period='3'
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.wifinet2.dtim_period='3'
fi

#Reassociation deadline
if [[ "$deployment" == "home.lan" || "$deployment" == "rob.lan" ]]; then
	uci set wireless.default_radio1.reassociation_deadline='20000'
	uci set wireless.wifinet2.reassociation_deadline='20000'
fi

#802.11r: Fast BSS transition
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.default_radio0.ieee80211r='0'
	uci set wireless.default_radio1.ieee80211r='1'
	uci set wireless.wifinet2.ieee80211r='1'

	uci set wireless.default_radio1.mobility_domain='123D'
	uci set wireless.wifinet2.mobility_domain='123F'

	uci set wireless.default_radio1.ft_over_ds='0'
        uci set wireless.wifinet2.ft_over_ds='0'

        uci set wireless.default_radio1.ft_psk_generate_local='1'
        uci set wireless.wifinet2.ft_psk_generate_local='1'
elif [[ "$deployment" == "rob.lan" ]]; then
        uci set wireless.default_radio0.ieee80211r='1'
        uci set wireless.default_radio1.ieee80211r='1'

        uci set wireless.default_radio0.mobility_domain='123A'
        uci set wireless.default_radio1.mobility_domain='123B'

        uci set wireless.default_radio0.ft_over_ds='0'
        uci set wireless.default_radio1.ft_over_ds='0'

        uci set wireless.default_radio0.ft_psk_generate_local='1'
        uci set wireless.default_radio1.ft_psk_generate_local='1'
fi

#802.11k: BSS transitions (needs fancy hostapd/wpad?)
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.default_radio0.ieee80211k='0'
	uci set wireless.default_radio1.ieee80211k='1'
	uci set wireless.wifinet2.ieee80211k='1'
elif [[ "$deployment" == "rob.lan" ]]; then
        uci set wireless.default_radio0.ieee80211k='1'
        uci set wireless.default_radio1.ieee80211k='1'
fi

#802.11v: Network Assisted Power Savings/Roaming (needs fancy hostapd/wpad)
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.default_radio0.bss_transition='1'
	uci set wireless.default_radio1.bss_transition='1'
	uci set wireless.wifinet2.bss_transition='1'
	uci set wireless.default_radio0.wnm_sleep_mode='1'
	uci set wireless.default_radio1.wnm_sleep_mode='1'
	uci set wireless.wifinet2.wnm_sleep_mode='1'
	uci set wireless.default_radio0.wnm_sleep_mode_no_keys='1'
	uci set wireless.default_radio1.wnm_sleep_mode_no_keys='1'
	uci set wireless.wifinet2.wnm_sleep_mode_no_keys='1'
elif [[ "$deployment" == "rob.lan" ]]; then
        uci set wireless.default_radio0.bss_transition='1'
        uci set wireless.default_radio1.bss_transition='1'
        uci set wireless.default_radio0.wnm_sleep_mode='1'
        uci set wireless.default_radio1.wnm_sleep_mode='1'
        uci set wireless.default_radio0.wnm_sleep_mode_no_keys='1'
        uci set wireless.default_radio1.wnm_sleep_mode_no_keys='1'
fi

#802.11w: Protected Management Frames (needs fancy hostapd/wpad, could break roaming)
	#802.11w optional or required (1 or 2, respectively) can prevent old or crappy clients from connecting
        	#chromecast requires 0 (appears to work with 1, but casting doesn't work properly)
        	#old wifi printer requires 0
        	#oldish homekit wifi thermostat requires 0
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.default_radio0.ieee80211w='0'
	uci set wireless.default_radio1.ieee80211w='2'
	uci set wireless.wifinet2.ieee80211w='0'
elif [[ "$deployment" == "rob.lan" ]]; then
        uci set wireless.default_radio0.ieee80211w='0'
        uci set wireless.default_radio1.ieee80211w='0'
fi

#Inactivity
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.default_radio0.disassoc_low_ack='0'
#	uci set wireless.default_radio1.disassoc_low_ack='0'
#	uci set wireless.wifinet2.disassoc_low_ack='0'
fi

#KRACK mitigation
uci set wireless.default_radio0.wpa_disable_eapol_key_retries='1'
uci set wireless.default_radio1.wpa_disable_eapol_key_retries='1'
if [[ "$deployment" == "home.lan" ]]; then
	uci set wireless.wifinet2.wpa_disable_eapol_key_retries='1'
fi

#Enable wifi if disabled
printf '%s\n' "Enabling wifi, ignore 2 messages about Entry not found"
uci del wireless.radio0.disabled
uci del wireless.radio1.disabled


#########################################################
printf '%s\n' "#Generic uci misc config"
if [[ "$(uci show | grep -i uhttpd)" != "" ]] ; then
        uci set uhttpd.main.redirect_https='on'
fi
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'

EOI

##############################
printf '%s\n' "SSH key config"
##############################
#Copies your ~/.ssh/authorized_keys content to openwrt, line by line
if [[ -f ~/.ssh/authorized_keys ]] ; then
	authkeys_lines="$(wc -l < ~/.ssh/authorized_keys)"
	for iLine in $(seq 1 "$authkeys_lines") ; do
		authkey_i="$(cat ~/.ssh/authorized_keys | head -n $iLine | tail -n 1)"
		if [[ "$iLine" == "1" ]] ; then
			command_i="$(printf '%s\n' "sshpass -p \"\" ssh -T root@192.168.1.1 printf '%s\n' \"$authkey_i\" > /etc/dropbear/authorized_keys")"
		else
                        command_i="$(printf '%s\n' "sshpass -p \"\" ssh -T root@192.168.1.1 printf '%s\n' \"$authkey_i\" >> /etc/dropbear/authorized_keys")"
		fi
		$command_i
	done
else
	printf '%s\n' "WARN: Skipping SSH key configuration because ~/.ssh/authorized_keys does not exist on the local host"
fi

############################################
printf '%s\n' "Board-specific Configuration"
############################################
if [[ "$board_id" == "dlink,dir-1935-a1" ]]	&& [[ "$firstMAC" == "2f2d078888c469b9fd22500225f65b2825c09d143e5958e170401993885bc800  -" ]] ; then
	sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	uci set system.@system[0].hostname='DIR1935'
	uci set wireless.radio0.channel='1'
	uci set wireless.radio1.channel='36'
EOI
	#Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-867-a1" ]] 	&& [[ "$firstMAC" == "f6168da64f313b5a63f3c23b67ac56f2f202d258758deee5d82abc3ac35b60b1  -" ]] ; then
	sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	uci set system.@system[0].hostname='DIR867'
	uci set wireless.radio0.channel='6'
	uci set wireless.radio1.channel='44'
EOI
	#Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-882-a1" ]]	&& [[ "$firstMAC" == "cc6d054aaf40b90e75c64ae18159c2784c5c27c526e58289dc1018f7585d7d33  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set system.@system[0].hostname='DIR882'
        uci set wireless.radio0.channel='11'
        uci set wireless.radio1.channel='149'
EOI
        #Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-1960-a1" ]]	&& [[ "$firstMAC" == "031aa1796dda3ad330512accf740f47fdca32ab07750fce551fecef3bfb7e0cb  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set system.@system[0].hostname='DIR1960'
        uci set wireless.radio0.channel='11'
        uci set wireless.radio1.channel='149'
EOI
        #Do not indent EOI. Causes issues.
elif [[ "$board_id" == "tplink,archer-c7-v4" ]]	&& [[ "$firstMAC" == "01acfe236ec608972388544e25a83e3c468785c4ea810257f2c04f7d89755195  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set system.@system[0].hostname='archerc7v4'
EOI
        #Do not indent EOI. Causes issues.
elif [[ "$board_id" == "tplink,archer-c7-v2" ]] && [[ "$firstMAC" == "d4eecffb3168c08a373179566f6a42d524ecc67c21593428a9f0a8ff17a7b093  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set system.@system[0].hostname='archerc7v2'
EOI
        #Do not indent EOI. Causes issues.
else
	printf '%s\n' "ERROR in provision.sh: board_id and firstMAC combination are unknown. Configure script for your board & settings before running."
	exit 1
fi
####################################################
printf '%s\n' "### Calling provision_secrets.sh ###"
####################################################
"$(dirname "${BASH_SOURCE[0]}")/SECRET/provision_secrets.sh"

####################################################
printf '%s\n' "### Printing pending uci changes ###"
####################################################
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
uci changes
EOI

#############################################################
printf '%s\n' "### Commiting uci changes and wrapping up ###"
#############################################################
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
uci commit
EOI
printf '%s\n' "About to change root pwd for $board_id: $firstMAC"
ssh root@192.168.1.1 passwd
printf '%s\n' "All done, about to ssh back in to reboot openwrt"
ssh -T root@192.168.1.1 reboot
printf '%s\n' "End of script"
