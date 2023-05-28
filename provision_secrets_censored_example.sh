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

################################################
printf '%s\n' "Generic uci secret configuration"
sshpass -p "" ssh -T root@192.168.1.1 <<\EOI

uci set wireless.default_radio1.ssid='My2ndRadioMainSSID'
uci set wireless.wifinet2.ssid='My2ndRadioAlternateSSID'

uci set wireless.default_radio0.key='MyFirstRadioPassword'
uci set wireless.default_radio1.key='MySecondRadioMainSSIDPassword'
uci set wireless.wifinet2.key='MySecondRadioAlternateSSIDPassword'
EOI


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
else
        printf '%s\n' "ERROR: board_id and firstMAC combination are unknown. Configure script for your board & settings before running."
        exit 1
fi
