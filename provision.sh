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

################################################################
printf '%s\n' "Clearing 192.168.1.1 from ~/.ssh/authorized_keys"
################################################################
ssh-keygen -f ~/.ssh/known_hosts -R "192.168.1.1"

#########################################
printf '%s\n' "Get board_id and firstMAC"
#########################################
board_id="$(sshpass -p "" ssh -o StrictHostKeyChecking=no -T root@192.168.1.1 grep '\"id\":\ ' /etc/board.json | sed 's;\"\,.*;;' | sed 's;.*\";;')"
firstMAC="$(sshpass -p "" ssh -T root@192.168.1.1 ip addr show | grep link/ether | head -n 1 | awk '{print $2}' | sha256sum)"
	#Stored and compared as sha256sum

if [[ "$board_id" == "" ]] || [[ "$firstMAC" == "" ]] ; then
	printf '%s\n' "ERROR: Was not able to get board_id and/or firstMAC via ssh"
	printf '%s\n' "board_id: $board_id"
	printf '%s\n' "firstMAC: $firstMAC"
	exit 1
fi

################################################################
printf '%s\n' "Checking that desired version of wpad is present"
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
wpad_package="wpad-openssl"
wpad_installed="$(opkg list-installed | grep wpad | awk '{print $1}')"
if [[ "$(printf '%s\n' "$wpad_installed" | wc -l )" != "1" ]] ; then
	printf '%s\n' "ERROR: Multiple wpad packages installed. Unclear which to remove"
	exit 1
elif [[ "$(printf '%s\n' "$wpad_installed" | grep "$wpad_package" | wc -l )" != "1" ]] ; then
        printf '%s\n' "Removing $wpad_installed"
	opkg update && opkg remove "$wpad_installed" && opkg install wpad-openssl && reboot
fi
EOI
sleep 60 #Increase if router doesn't come back online fast enough

###########################################
printf '%s\n' "First big batch of commands"
###########################################
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI

################################
printf '%s\n' "Getting board id"
board_id="$(grep "\"id\":\ " /etc/board.json | sed 's;\"\,.*;;' | sed 's;.*\";;')"
if [[ "$(printf '%s\n' $board_id | wc -l)" != "1" ]] ; then
	printf '%s\n' "ERROR: Failed to get board id from /etc/board.json"
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
	*)
		board_tested=false
		;;
esac
if [[ "$board_tested" != "true" ]] ; then
	printf '%s\n' "ERROR: Board id from /etc/board.json does not match tested_board_ids. Need to customize provision...sh to support this board first"
	exit 1
fi

#########################################
printf '%s\n' "Generic non-uci config"

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

#########################################
printf '%s\n' "Generic uci system config"
uci revert system
uci set system.@system[0].zonename='America/Toronto'
uci set system.@system[0].timezone='EST5EDT,M3.2.0,M11.1.0'
uci set system.ntp.use_dhcp='0'
        #Automatic NTP sync doesn't work after reboot when this is set to 1. Functionality may depend on dnsmasq or another disabled feature
uci add_list system.ntp.server='10.0.0.1'
uci add_list system.ntp.server='10.1.0.1'
uci add_list system.ntp.server='10.2.0.1'
uci add_list system.ntp.server='10.3.0.1'
uci add_list system.ntp.server='10.4.0.1'
        #My router's ip addresses. It runs an NTP server.

##########################################
printf '%s\n' "Generic uci network config"
uci revert network

#This block reassigns the wan port to the main/LAN bridge.
#If you're using openwrt as a router, you will probably want to change code that modifies:
	#uci network*: can omit entirely if you aren't using VLANs
	#uci wireless.*.network: change value to 'lan' if you aren't using VLANs with your wifi networks
if [[ "$(uci show | grep '^network.wan6.*')" != "" ]] ; then
        uci delete network.wan6
fi
if [[ "$(uci show | grep '^network.wan.*')" != "" ]] ; then
	uci delete network.wan
fi
if [[ "$(uci show | grep "network.\@device\[0\].ports" | grep wan)" == "" ]] ; then
	uci add_list network.@device[0].ports='wan'
fi

uci add network bridge-vlan >> /dev/null
	#If copying this line from LuCi, it will have a comment with the auto generated ID of the bridge
	#Consider removing the comment (i.e. everything after #) to prevent future confusion
	#Added redirection to /dev/null to quiet output
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='100'
uci add_list network.@bridge-vlan[-1].ports='wan:t'
uci add network bridge-vlan >> /dev/null
	#If copying this line from LuCi, it will have a comment with the auto generated ID of the bridge
	#Consider removing the comment (i.e. everything after #) to prevent future confusion
	#Added redirection to /dev/null to quiet output
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='200'
uci add_list network.@bridge-vlan[-1].ports='wan:t'
uci add network bridge-vlan >> /dev/null
	#If copying this line from LuCi, it will have a comment with the auto generated ID of the bridge
	#Consider removing the comment (i.e. everything after #) to prevent future confusion
	#Added redirection to /dev/null to quiet output
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='300'
uci add_list network.@bridge-vlan[-1].ports='wan:t'
uci add network bridge-vlan >> /dev/null
	#If copying this line from LuCi, it will have a comment with the auto generated ID of the bridge
	#Consider removing the comment (i.e. everything after #) to prevent future confusion
	#Added redirection to /dev/null to quiet output
uci set network.@bridge-vlan[-1].device='br-lan'
uci set network.@bridge-vlan[-1].vlan='400'
uci add_list network.@bridge-vlan[-1].ports='lan1:u*'
uci add_list network.@bridge-vlan[-1].ports='lan2:u*'
uci add_list network.@bridge-vlan[-1].ports='lan3:u*'
uci add_list network.@bridge-vlan[-1].ports='lan4:u*'
uci add_list network.@bridge-vlan[-1].ports='wan:t'

uci set network.KLAN=interface
uci set network.KLAN.proto='dhcp'
uci set network.KLAN.device='br-lan.100'
uci set network.KLAN.delegate='0'
uci set network.KWLAN=interface
uci set network.KWLAN.proto='dhcp'
uci set network.KWLAN.device='br-lan.200'
uci set network.KWLAN.delegate='0'
uci set network.IOT=interface
uci set network.IOT.proto='none'
uci set network.IOT.device='br-lan.300'
uci set network.MLAN=interface
uci set network.MLAN.proto='none'
uci set network.MLAN.device='br-lan.400'
uci del network.lan

### Radio settings ###
uci revert wireless
uci set wireless.radio0.channel='1' #PLACEHOLDER
uci set wireless.radio1.channel='36' #PLACEHOLDER
uci set wireless.radio0.htmode='HT40'
uci set wireless.radio1.htmode='VHT40'
uci set wireless.radio0.country='CA'
uci set wireless.radio1.country='CA'
uci set wireless.radio0.cell_density='0'
uci set wireless.radio1.cell_density='3'

### Add new wifi network ###
uci set wireless.wifinet2=wifi-iface
uci set wireless.wifinet2.device='radio1'
uci set wireless.wifinet2.mode='ap'

### Wifi network settings ###
uci set wireless.default_radio0.ssid='PLACEHOLDER'
uci set wireless.default_radio1.ssid='PLACEHOLDER2'
uci set wireless.wifinet2.ssid='PLACEHOLDER3'

uci set wireless.default_radio0.network='IOT'
uci set wireless.default_radio1.network='KWLAN'
uci set wireless.wifinet2.network='MLAN'

uci set wireless.default_radio0.dtim_period='1'
uci set wireless.default_radio1.dtim_period='3'
uci set wireless.wifinet2.dtim_period='3'

uci set wireless.default_radio0.encryption='psk2+ccmp'
uci set wireless.default_radio1.encryption='psk2+ccmp'
uci set wireless.wifinet2.encryption='psk2+ccmp'

uci set wireless.default_radio0.key='PLACEHOLDER'
uci set wireless.default_radio1.key='PLACEHOLDER'
uci set wireless.wifinet2.key='PLACEHOLDER'

#802.11r
uci set wireless.default_radio0.ieee80211r='0'
uci set wireless.default_radio1.ieee80211r='1'
uci set wireless.wifinet2.ieee80211r='1'

uci set wireless.default_radio1.mobility_domain='123D'
uci set wireless.wifinet2.mobility_domain='123F'

uci set wireless.default_radio1.ft_over_ds='0'
uci set wireless.wifinet2.ft_over_ds='0'

uci set wireless.default_radio1.ft_psk_generate_local='1'
uci set wireless.wifinet2.ft_psk_generate_local='1'

uci set wireless.default_radio1.reassociation_deadline='20000'
uci set wireless.wifinet2.reassociation_deadline='20000'

#802.11k (needs fancy hostapd/wpad)
uci set wireless.default_radio0.ieee80211k='0'
uci set wireless.default_radio1.ieee80211k='1'
uci set wireless.wifinet2.ieee80211k='1'

#802.11v (needs fancy hostapd/wpad)
uci set wireless.default_radio0.bss_transition='1'
uci set wireless.default_radio1.bss_transition='1'
uci set wireless.wifinet2.bss_transition='1'
uci set wireless.default_radio0.wnm_sleep_mode='1'
uci set wireless.default_radio1.wnm_sleep_mode='1'
uci set wireless.wifinet2.wnm_sleep_mode='1'
uci set wireless.default_radio0.wnm_sleep_mode_no_keys='1'
uci set wireless.default_radio1.wnm_sleep_mode_no_keys='1'
uci set wireless.wifinet2.wnm_sleep_mode_no_keys='1'

#802.11w (needs fancy hostapd/wpad), could break roaming
uci set wireless.default_radio0.ieee80211w='2'
uci set wireless.default_radio1.ieee80211w='2'
uci set wireless.wifinet2.ieee80211w='2'

#Inactivity
uci set wireless.default_radio0.disassoc_low_ack='0'
uci set wireless.default_radio1.disassoc_low_ack='0'
uci set wireless.wifinet2.disassoc_low_ack='0'

#KRACK mitigation
uci set wireless.default_radio0.wpa_disable_eapol_key_retries='1'
uci set wireless.default_radio1.wpa_disable_eapol_key_retries='1'
uci set wireless.wifinet2.wpa_disable_eapol_key_retries='1'

uci del wireless.radio0.disabled
uci del wireless.radio1.disabled


#########################################################
printf '%s\n' "Generic uci misc config"
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
if [[ "$board_id" == "dlink,dir-1935-a1" ]] && [[ "$firstMAC" == "2f2d078888c469b9fd22500225f65b2825c09d143e5958e170401993885bc800  -" ]] ; then
	sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	uci set system.@system[0].hostname='DIR1935'
	uci set wireless.radio0.channel='1'
	uci set wireless.radio1.channel='36'
EOI
	#Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-867-a1" && "$firstMAC" == "f6168da64f313b5a63f3c23b67ac56f2f202d258758deee5d82abc3ac35b60b1  -" ]] ; then
	sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	uci set system.@system[0].hostname='DIR867'
	uci set wireless.radio0.channel='6'
	uci set wireless.radio1.channel='44'
EOI
	#Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-882-a1" && "$firstMAC" == "cc6d054aaf40b90e75c64ae18159c2784c5c27c526e58289dc1018f7585d7d33  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set system.@system[0].hostname='DIR882'
        uci set wireless.radio0.channel='11'
        uci set wireless.radio1.channel='149'
EOI
        #Do not indent EOI. Causes issues.
else
	printf '%s\n' "ERROR: board_id and firstMAC combination are unknown. Configure script for your board & settings before running."
	exit 1
fi
############################################
printf '%s\n' "Calling provision_secrets.sh"
"$(dirname "${BASH_SOURCE[0]}")/SECRET/provision_secrets.sh"

###########################
printf '%s\n' "Commiting uci changes and wrapping up"
###########################
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
uci commit
EOI
printf '%s\n' "About to change root pwd"
ssh root@192.168.1.1 passwd
printf '%s\n' "All done, about to ssh back in to reboot openwrt"
ssh -T root@192.168.1.1 reboot
printf '%s\n' "End of script"
