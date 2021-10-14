#!/bin/bash
# /netboot/http/www/Nokia_Deep/Cleanup.sh

sleep 15

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Cleanup - Running install cleanup |& tee -a /install.log
echo $dt == Cleanup - Running install cleanup

echo $dt == Cleanup - Removing Cleanup service |& tee -a /install.log
echo $dt == Cleanup - Removing Cleanup service
systemctl disable Cleanup.service
rm -f /etc/systemd/system/Cleanup.service

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Cleanup - Converting all unassigned drives to indvidial Array/R0 pairs |& tee -a /install.log
echo $dt == Cleanup - Converting all unassigned drives to indvidial Array/R0 pairs

ssacli controller slot=0 create type=arrayr0 drives=allunassigned

hwsn=$( cat /sys/class/dmi/id/product_serial )

while IFS==, read -r Server_Name ILO_Name ILO_User ILO_DEF_PASS ILO_MAC ILO_IPv4 ILO_IPv4_GW ILO_IPv4_Network ILO_IPv4_NM ILO_IPv6 ILO_IPv6_GW eno1_IPv4 eno1_IPv4_GW eno1_IPv4_Network eno1_IPv4_NM eno1_IPv6 eno1_IPv6_GW eno1_IPv6_NM SerialNumber log_target image_server ; do

  echo Checking $SerialNumber
  if [[ "$hwsn" == "$SerialNumber" ]] ; then
		echo $dt == Cleanup - Matching hwsn success |& tee -a /install.log
		echo $dt == Cleanup - Matching hwsn success
		break
  fi

done < /sysdata.txt

echo Server serial number - $hwsn |& tee -a /install.log
echo |& tee -a /install.log

memtotal=$( cat /proc/meminfo | grep MemTotal )

echo "Memory capacity presented by cat /proc/meminfo is:"$memtotal":" |& tee -a /install.log

# MemTotal = Total usable RAM (i.e. physical RAM minus a few reserved bits and the kernel binary code)

if [[ "$memtotal" == *"19668"* ]]; then
  echo "Memory capacity is consistent with the baseline" |& tee -a /install.log
else
  echo "Memory capacity is not consistent with baseline" |& tee -a /install.log
fi

echo |& tee -a /install.log

ifconfig -a eno1  |& tee -a /install.log

echo |& tee -a /install.log

echo |& tee -a /install.log
echo =============================================== |& tee -a /install.log
echo |& tee -a /install.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - df -h of host |& tee -a /install.log
echo $dt == Deep_Init - df -h of host
df -h  |& tee -a /install.log

echo |& tee -a /install.log
echo =============================================== |& tee -a /install.log
echo |& tee -a /install.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - lsblk of host |& tee -a /install.log
echo $dt == Deep_Init - lsblk of host
lsblk  |& tee -a /install.log

echo |& tee -a /install.log
echo =============================================== |& tee -a /install.log
echo |& tee -a /install.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - vgdisplay of host |& tee -a /install.log
echo $dt == Deep_Init - vgdisplay of host
vgdisplay  |& tee -a /install.log

echo |& tee -a /install.log
echo =============================================== |& tee -a /install.log
echo |& tee -a /install.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Cleanup - Pushing logs to image host |& tee -a /install.log
echo $dt == Cleanup - Pushing logs to image host

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Pushing logs to image host |& tee -a /install.log
echo $dt == Deep_Init - Pushing logs to image host

/sshpass -p "enter_passwd" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no /install.log root@$log_target:/netboot/Nokia_Deep/Host_Logs/$hwsn.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Cleaning up RSA Keys and SSACLI package|& tee -a /install.log
echo $dt == Deep_Init - Cleaning up RSA Keys and SSACLI package

apt-get remove ssacli -y
apt-key del "FB41 0E68 CEDF 95D0 6681  1E95 527B C53A 2689 B887"
apt-key del "5744 6EFD E098 E5C9 34B6  9C7D C208 ADDE 26C2 B797"
apt-key del "476D ADAC 9E64 7EE2 7453  F2A3 B070 680A 5CE2 D476"
apt-key del "882F 7199 B20F 94BD 7E3E  690E FADD 8D64 B127 5EA3"

#rm -f /DF_sysdata.txt
#rm -f /sshpass
#rm -f /ssa.deb
#rm -f /hpePublicKey2048_key1.pub
#rm -f /hpPublicKey1024.pub
#rm -f /hpPublicKey2048_key1.pub
#rm -f /hpPublicKey2048.pub
#rm -f /Deep_Init.sh
#rm -f /install.log
#rm -f /Cleanup.sh

wall "System configuration complete"

#shutdown -h now