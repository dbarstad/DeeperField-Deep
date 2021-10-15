#!/bin/bash
# /netboot/http/www/Charter/Deep_Init.sh

sleep 15

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Importing DF_sysdata.txt |& tee -a /install.log
echo $dt == Deep_Init - Importing DF_sysdata.txt

hwsn=$( cat /sys/class/dmi/id/product_serial )

while IFS==, read -r Server_Name ILO_Name ILO_User ILO_DEF_PASS ILO_MAC ILO_IPv4 ILO_IPv4_GW ILO_IPv4_Network ILO_IPv4_NM ILO_IPv6 ILO_IPv6_GW eno1_IPv4 eno1_IPv4_GW eno1_IPv4_Network eno1_IPv4_NM eno1_IPv6 eno1_IPv6_GW eno1_IPv6_NM SerialNumber log_target image_server ; do

  echo Checking $SerialNumber 
  if [[ "$hwsn" == "$SerialNumber" ]] ; then
		echo $dt == Deep_Init - Matching hwsn success |& tee -a /install.log
		echo $dt == Deep_Init - Matching hwsn success
		break
  fi

done < /DF_sysdata.txt

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Pulling additional files |& tee -a /install.log
echo $dt == Deep_Init - Pulling additional files

echo $dt == Deep_Init - pulling additional content from http://$dhcphost/Nokia_Deep/ |& tee -a /install.log
echo $dt == Deep_Init - pulling additional content from http://$dhcphost/Nokia_Deep/

#wget -P / http://$image_server/Nokia_Deep/DF_sysdata.txt
wget -P / http://$image_server/Nokia_Deep/sshpass
chmod 777 /sshpass
wget -P / http://$image_server/Nokia_Deep/ssa.deb
wget -P / http://$image_server/Nokia_Deep/hpePublicKey2048_key1.pub
wget -P / http://$image_server/Nokia_Deep/hpPublicKey1024.pub
wget -P / http://$image_server/Nokia_Deep/hpPublicKey2048_key1.pub
wget -P / http://$image_server/Nokia_Deep/hpPublicKey2048.pub
wget -P / http://$image_server/Nokia_Deep/Cleanup.sh
chmod 777 /Cleanup.sh
apt-key add /hpePublicKey2048_key1.pub
apt-key add /hpPublicKey1024.pub
apt-key add /hpPublicKey2048.pub
apt-key add /hpPublicKey2048_key1.pub
dpkg -i /ssa.deb

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Drop drive spares |& tee -a /install.log
echo $dt == Deep_Init - Drop drive spares

ssacli controller slot=0 array a remove spares=2I:3:7,2I:3:8

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Setting root password |& tee -a /install.log
echo $dt == Deep_Init - Setting root password

sudo su –
echo "root:remove for security" | chpasswd

echo  |& tee -a /install.log
echo  |& tee -a /install.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Setting timezone |& tee -a /install.log
echo $dt == Deep_Init - Setting timezone
cd /etc
rm localtime
ln –s /usr/share/zoneinfo/EST5EDT localtime

echo  |& tee -a /install.log
echo  |& tee -a /install.log

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Setting eno1 IF details |& tee -a /install.log
echo $dt == Deep_Init - Setting eno1 IF details

echo "" >> /etc/network/interfaces
echo "" >> /etc/network/interfaces
echo #Config for eno1 >> /etc/network/interfaces
echo auto eno1 >> /etc/network/interfaces
echo #IPv4 for eno1 >> /etc/network/interfaces
echo iface eno1 inet static >> /etc/network/interfaces
echo "  " address $eno1_IPv4  >> /etc/network/interfaces
echo "  " gateway $eno1_IPv4_GW >> /etc/network/interfaces
echo "  " netmask $eno1_IPv4_NM >> /etc/network/interfaces
echo "" >> /etc/network/interfaces
echo #IPv6 for eno1 >> /etc/network/interfaces
echo iface eno1 inet6 static >> /etc/network/interfaces
echo "  " pre-up modprobe ipv6 >> /etc/network/interfaces
echo "  " address $eno1_IPv6 >> /etc/network/interfaces
echo "  " gateway $eno1_IPv6_GW >> /etc/network/interfaces
echo "  " netmask 64 >> /etc/network/interfaces
echo "" >> /etc/network/interfaces

echo  |& tee -a /install.log
echo  |& tee -a /install.log

# /etc/init.d/networking restart

sleep 10

dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Configuraiton complete.  Preparing Cleanup.sh on reboot. |& tee -a /install.log
echo $dt == Deep_Init - Configuraiton complete.  Preparing Cleanup.sh on reboot.


dt=`date '+%d/%m/%Y_%H:%M:%S'`
echo $dt == Deep_Init - Configuring final script for drive configuration and cleanup after reboot |& tee -a /install.log
echo $dt == Deep_Init - Configuring final script for drive configuration and cleanup after reboot

echo [Unit] >> /etc/systemd/system/Cleanup.service
echo Description=Invoke Cleanup script  >> /etc/systemd/system/Cleanup.service
echo After=network-online.target  >> /etc/systemd/system/Cleanup.service
echo  >> /etc/systemd/system/Cleanup.service
echo [Service]  >> /etc/systemd/system/Cleanup.service
echo Type=simple  >> /etc/systemd/system/Cleanup.service
echo ExecStart=/Cleanup.sh  >> /etc/systemd/system/Cleanup.service
echo TimeoutStartSec=0  >> /etc/systemd/system/Cleanup.service
echo  >> /etc/systemd/system/Cleanup.service
echo [Install]  >> /etc/systemd/system/Cleanup.service
echo WantedBy=default.target  >> /etc/systemd/system/Cleanup.service

systemctl daemon-reload
systemctl enable Cleanup.service

reboot