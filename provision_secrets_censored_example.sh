#!/bin/bash -e
#Configures sensitive aspects of openwrt (e.g., wifi passwords)

#########################################
printf '%s\n' "Get board_id and firstMAC (again)"
#########################################
board_id="$(sshpass -p "" ssh -T root@192.168.1.1 grep '\"id\":\ ' /etc/board.json | sed 's;\"\,.*;;' | sed 's;.*\";;')"
firstMAC="$(sshpass -p "" ssh -T root@192.168.1.1 ip addr show | grep link/ether | head -n 1 | awk '{print $2}' | sha256sum)"
        #Stored and compared as sha256sum

if [[ "$board_id" == "" ]] || [[ "$firstMAC" == "" ]] ; then
        printf '%s\n' "ERROR: Was not able to get board_id and/or firstMAC via ssh"
        printf '%s\n' "board_id: $board_id"
        printf '%s\n' "firstMAC: $firstMAC"
        exit 1
fi

#######################################################
printf '%s\n' "Decide which deployment settings to use"
#######################################################

if [[ ("$board_id" == "dlink,dir-1935-a1" && "$firstMAC" == "2f2d078888c469b9fd22500225f65b2825c09d143e5958e170401993885bc800  -") \
   || ("$board_id" == "dlink,dir-867-a1"  && "$firstMAC" == "f6168da64f313b5a63f3c23b67ac56f2f202d258758deee5d82abc3ac35b60b1  -") \
   || ("$board_id" == "dlink,dir-882-a1"  && "$firstMAC" == "cc6d054aaf40b90e75c64ae18159c2784c5c27c526e58289dc1018f7585d7d33  -") \
   || ("$board_id" == "dlink,dir-1960-a1" && "$firstMAC" == "031aa1796dda3ad330512accf740f47fdca32ab07750fce551fecef3bfb7e0cb  -") ]] ; then
        deployment="home.lan"
elif [[ ("$board_id" == "tplink,archer-c7-v4" && "$firstMAC" == "01acfe236ec608972388544e25a83e3c468785c4ea810257f2c04f7d89755195  -") \
     || ("$board_id" == "tplink,archer-c7-v2" && "$firstMAC" == "d4eecffb3168c08a373179566f6a42d524ecc67c21593428a9f0a8ff17a7b093  -") ]] ; then
        deployment="rob.lan"
else
        printf '%s\n' "ERROR in provision_secrets.sh: board_id and firstMAC combination are unknown. Configure script for your board & settings before running."
        exit 1
fi

################################################
printf '%s\n' "Generic uci secret configuration"
if [[ "$deployment" == "home.lan" ]]; then
	sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	uci set wireless.default_radio1.ssid='My2ndRadioMainSSID'
	uci set wireless.wifinet2.ssid='My2ndRadioAlternateSSID'

	uci set wireless.default_radio0.key='MyFirstRadioPassword'
	uci set wireless.default_radio1.key='MySecondRadioMainSSIDPassword'
	uci set wireless.wifinet2.key='MySecondRadioAlternateSSIDPassword'
EOI
	#Do not indent EOI. Causes issues.
elif [[ "$deployment" == "rob.lan" ]]; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
	uci set wireless.default_radio0.ssid='MyFirstRadioSSID'
        uci set wireless.default_radio1.ssid='MySecondRadioSSID'

        uci set wireless.default_radio0.key='MyFirstRadioPassword'
        uci set wireless.default_radio1.key='MySecondRadioPassword'
EOI
        #Do not indent EOI. Causes issues.
fi

############################################
printf '%s\n' "Board-specific secret configuration"
############################################
if [[ "$board_id" == "dlink,dir-1935-a1" ]] && [[ "$firstMAC" == "2f2d078888c469b9fd22500225f65b2825c09d143e5958e170401993885bc800  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set wireless.default_radio0.ssid='My1stRadioSSID'
EOI
        #Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-867-a1" && "$firstMAC" == "f6168da64f313b5a63f3c23b67ac56f2f202d258758deee5d82abc3ac35b60b1  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set wireless.default_radio0.ssid='My1stRadioSSID'
EOI
        #Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-882-a1" && "$firstMAC" == "cc6d054aaf40b90e75c64ae18159c2784c5c27c526e58289dc1018f7585d7d33  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set wireless.default_radio0.ssid='My1stRadioSSID'
EOI
        #Do not indent EOI. Causes issues.
elif [[ "$board_id" == "dlink,dir-1960-a1" && "$firstMAC" == "031aa1796dda3ad330512accf740f47fdca32ab07750fce551fecef3bfb7e0cb  -" ]] ; then
        sshpass -p "" ssh -T root@192.168.1.1 <<\EOI
        uci set wireless.default_radio0.ssid='My1stRadioSSID'
EOI
        #Do not indent EOI. Causes issues.
#else
#        printf '%s\n' "ERROR: board_id and firstMAC combination are unknown. Configure script for your board & settings before running."
#        exit 1
fi
