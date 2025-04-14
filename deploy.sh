#!/bin/bash

#    This file is part of osic4MVS.
#
#    Copyright (C) 2021 choupit0
#
#    osic4MVS is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    osic4MVS is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with osic4MVS.  If not, see <https://www.gnu.org/licenses/>.
#
# Script Name    : deploy.sh
# Description    : This script is part of osic4MVS.sh main script but it could be launch alone if needed.
#                  It's only available for Debian OS family.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20250414
# Version        : 1.0.1
# Usage          : ./osic4MVS.sh
# Prerequisites  : N/A

sudo su

temp_folder="$(mktemp -d /tmp/temp_folder-XXXXXXXX)"

# Installing the prerequisites packages
echo -n -e "\r                                       "
echo -n -e "\r[-] Updating and upgrading the packages lists..."

apt-get update > /dev/null 2>&1
echo -n -e "\r                                               "
echo -n -e "\r[-] Installing the prerequisites packages...     "
apt-get install -y curl gpg git automake > /dev/null 2>&1

# MassVulScan installation
echo -n -e "\r                                               "
echo -n -e "\r[-] Installing MassVulScan...                 "
cd /tmp
git clone https://github.com/choupit0/MassVulScan.git
cd MassVulScan
./sources/installation.sh -auto-installation

sed -i 's/rate="1500"/rate="1200"/g' MassVulScan.sh

chown -R debian:debian /tmp/MassVulScan/

# MassVulScan execution
if [[ -d "/tmp/osic4MVS/hosts" && -d "/tmp/osic4MVS/xhosts" ]]; then
        hosts=$(find /tmp/osic4MVS/hosts -type f -exec basename '{}' \;)
        xhosts=$(find /tmp/osic4MVS/xhosts -type f -exec basename '{}' \;)
        ./MassVulScan.sh -f /tmp/osic4MVS/hosts/${hosts} -x /tmp/osic4MVS/xhosts/${xhosts} -a -r
elif [[ -d "/tmp/osic4MVS/hosts" ]]; then
        hosts=$(find /tmp/osic4MVS/hosts -type f -exec basename '{}' \;)
        ./MassVulScan.sh -f /tmp/osic4MVS/hosts/${hosts} -a -r
else
        echo -n -e "\r[X] ERROR - No hosts files.\n"
fi

exit 0
