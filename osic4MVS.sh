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

# Script Name    : osic4MVS.sh [a.k.a. OpenStack Instance Creation For MassVulScan]
# Description    : Create an OVH instance and deploy MassVulScan script on it (https://github.com/choupit0/MassVulScan).
#                  After deployment, a scan will be automatically launched against the IPv4 addresses or hostnames set in
#                  parameter(s).
#                  You will be able to follow remotely the deployment and scan from your station in a screen session.
#                  Reports will be automatically downloaded and OpenStack instance deleted at the end of the process.
#		   They can also be sent automatically by email.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# Date           : 20230324
# Version        : 1.0.1
# Usage          : ./osic4MVS.sh
# Prerequisites  : python-openstackclient or python3-openstackclient, s-nail (optional), screen, dnsutils, ipcalc, and netcat-openbsd packages
#                  Ping and SSH must be allowed from your server to the Internet
#                  An OVH account (https://www.ovh.com)
#                  Dedicated user and environment variables (Public Cloud / Management Interfaces / Users & Roles)
#                  Dedicated SSH key pair and PEM file (Public Cloud / Management Interfaces / Horizon / Key Pairs)

version="1.0.2"
bold_color="\033[1m"
purple_color="\033[1;35m"
green_color="\033[0;32m"
red_color="\033[1;31m"
blue_color="\033[0;36m"
end_color="\033[0m"
script_start="$SECONDS"

# Script to deploy and launch on the instance
deploy_script="./deploy.sh"

# Disable CTRL+C
trap '' SIGINT

# Name server used for the DNS queries/lookups
dns="1.1.1.1"

# Instance creation and deployement
# References:
#
# Flavors
#+--------------------------------------+-----------------+-----------+------+-----------+------+-------+-------------+-----------+
#| ID                                   | Name            | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
#+--------------------------------------+-----------------+-----------+------+-----------+------+-------+-------------+-----------+
#| a8a85ec5-12b4-4b05-8dc1-bd6bd02457d9 | s1-2            | 2000      | 10   | 0         |      | 1     | 1.0         | True      |
#| 92416632-fece-42f0-a6a4-70b2d416fa1d | s1-4            | 4000      | 20   | 0         |      | 1     | 1.0         | True      |
#
# Images:
#
#+--------------------------------------+-----------------------------------------------+--------+--------+
#| ID                                   | Name                                          | Status | Server |
#+--------------------------------------+-----------------------------------------------+--------+--------+
#| 71d85b91-dac6-485d-9e86-9ddb0c611da2 | Debian 10                                     | ACTIVE |        |
#| 955ff6dd-3962-49da-88ce-f3dd1b4f9d8c | Ubuntu 20.04                                  | ACTIVE |        |


# Optional part to receive email during the scanning process:
# When the scan is starting (and to get IPv4 instance), to receive the reports and when the Openstack instance is deleted
smtp_server="ssl0.ovh.net:587"				# Ex. ssl10.ovh.net:587 or smtp.provider.tld:25
from_address="scan@ovh.com"				# From/return email address Ex. scan@ovh.com
recipient=""						# Ex. user@acme.com, use space " " to add multiple recipients
auth_user_pass=""					# USER and PASSWORD are specified as part of an URL, they MUST be percent-encoded
							# s-nail offers the urlcodec command which does this for you:
							# printf 'urlcodec encode username@provider.tld' | s-nail -#
							#  username%40provider.tld
							# printf 'urlcodec encode MygreatPassword!' | s-nail -#
							#  MygreatPassword%21
							# And merge them separate by ":", like this:
							# username%40provider.tld:MygreatPassword%21
							# --set=mta=smtp[s]://username%40provider.tld:MygreatPassword%21@smtp.provider.tld[:port]
# If you don't use SMTP authentication, replace below:
#  "--set=mta=smtp://${auth_user_pass}@${smtp_server}" \ BY: "--set=mta=smtp://${smtp_server}" \
#  "--set=smtp-auth=login" \ BY: "--set=smtp-auth=none" \
# And remove these two lines:
# "--set=smtp-use-starttls" \
# "--set=tls-verify=strict" \

# Email part
email(){
subject="$1"
attachment="$2"

if [[ -z ${attachment} ]]; then
	s-nail -n \
	"--set=v15-compat" \
	"--set=from=${from_address}" \
	"--subject=${subject}" \
	"--set=mta=smtp://${auth_user_pass}@${smtp_server}" \
	"--set=smtp-auth=login" \
	"--set=smtp-use-starttls" \
	"--set=tls-verify=strict" \
	"--set=sendwait" \
	${recipient} < /dev/null
else
	s-nail -n \
	"--set=v15-compat" \
	"--set=from=${from_address}" \
	"--subject=${subject}" \
	"--attach=${attachment}" \
	"--set=mta=smtp://${auth_user_pass}@${smtp_server}" \
	"--set=smtp-auth=login" \
	"--set=smtp-use-starttls" \
	"--set=tls-verify=strict" \
	"--set=sendwait" \
	${recipient} < /dev/null
fi
}

# Root user?
root_user(){
if [[ $(id -u) != "0" ]]; then
        echo -e "${red_color}[X] You are not the root.${end_color}"
        echo "Assuming your are in the sudoers list, please launch the script with \"sudo\"."
        exit 1
fi
}

# Time elapsed
time_elapsed(){
script_end="$SECONDS"
script_duration="$((script_end-script_start))"

printf 'Duration: %02dh:%02dm:%02ds\n' $((${script_duration}/3600)) $((${script_duration}%3600/60)) $((${script_duration}%60))
}

# Verifying if you can reach Internet by Ping (ICMP type=8)
check_internet(){
echo -n -e "\r                                                                                "
echo -n -e "${blue_color}\r[-] Checking your Internet connectivity...${end_color}"
if ! ping -i 0.5 -c2 -W 1 1.1.1.1 &>/dev/null || ! ping -i 0.5 -W 1 -c2 9.9.9.9 &>/dev/null; then
	echo -e "${red_color}\r[X] Please, open the network flows for Ping and SSH to the Internet.${end_color}"
	echo -e "${red_color}[X] Or verify your network connectivity.${end_color}"
	exit 1
else
	echo -e "${green_color}\r[V] Internet access seems OK (ping to Cloudflare and Quad9 DNS)${end_color}                                          "
	
fi
}

# Logo
logo(){
if [[ $(command -v figlet) ]]; then
        my_logo="$(figlet -k osic4MVS)"
        echo -e "${green_color}${my_logo}${end_color}"
        echo -e "${purple_color}[a.k.a. OpenStack Instance Creation For MassVulScan]${end_color}"
        echo -e "${purple_color}[I] Version ${version}${end_color}"
else
        echo -e "${green_color}             _        _  _    __  __ __     __ ____"
        echo -e "${green_color}  ___   ___ (_)  ___ | || |  |  \/  |\ \   / // ___|"
        echo -e "${green_color} / _ \ / __|| | / __|| || |_ | |\/| | \ \ / / \___ \\"
        echo -e "${green_color}| (_) |\__ \| || (__ |__   _|| |  | |  \ V /   ___) |"
        echo -e "${green_color} \___/ |___/|_| \___|   |_|  |_|  |_|   \_/   |____/"
        echo -e "${end_color}"
        echo -e "${purple_color}[a.k.a. OpenStack Instance Creation For MassVulScan]${end_color}"
        echo -e "${purple_color}[I] Version ${version}${end_color}"
fi
}

clear

# Usage of script
usage(){
        logo
	echo -e "${purple_color}${bold_color}[I] Usage: Root user or sudo${end_color} ./$(basename "$0") [[-f file] + [-x file] + [-r rc-file] + [-k ssh-key] + [-p pub-key-name] | [-V] [-h]]"
	echo -e "${bold_color}    * Mandatory parameter:"
	echo -e "${blue_color}        -f | --include-file${end_color} \tFile including IPv4 addresses (CIDR format) and/or hostnames to scan (one by line)."
	echo -e "${blue_color}        -r | --rc-file${end_color} \t\tOpenStack RC file containing tenant-specific environment variables."
	echo -e "${blue_color}        -k | --ssh-key${end_color} \t\tPrivate SSH Key used to connect on the remote instance."
	echo -e "${blue_color}        -p | --pub-key${end_color} \t\tPublic SSH Key name created on the management interface (https://horizon.cloud.ovh.net/)."
	echo -e "${bold_color}    * Optional parameter:"
	echo -e "${blue_color}        -x | --exclude-file${end_color} \tFile including IPv4 addresses ONLY (CIDR format) to NOT scan (one by line)."
	echo -e "${bold_color}      Information:"
	echo -e "${blue_color}        -h | --help${end_color} \t\tThis help menu."
	echo -e "${blue_color}        -V | --version${end_color} \t\tScript version."
	echo ""
}

# Checking prerequisites
if [[ ! $(command -v ipcalc) ]] || [[ ! $(command -v screen) ]] || [[ ! $(command -v netcat) ]] || [[ ! $(command -v dig) ]]; then
        echo -e "${red_color}[X] There are some prerequisites to install before to launch this script.${end_color}"
        echo -e "${purple_color}[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
        echo "$(grep ^-- "requirements.txt")"
fi

# No paramaters
if [[ "$1" == "" ]]; then
	echo -e "${red_color}\n[X] Missing parameter.${end_color}"
        usage
        exit 1
fi

# Mandatory variables
hosts="$1"
rc_file=""
priv_key=""
pub_key_name=""
# Optional parameter
exclude_file=""

# Available parameters
while [[ "$1" != "" ]]; do
        case "$1" in
                -f | --include-file )
                        shift
                        hosts="$1"
			basename_hosts_file=$(basename ${hosts})
                        ;;
		-r | --rc-file )
			shift
			rc_file="$1"
			;;
		-k | --ssh-key )
			shift
			priv_key="$1"
			;;
		-p | --pub-key )
			shift
			pub_key_name="$1"
			;;
                -x | --exclude-file )
                        file_to_exclude="yes"
                        shift
                        exclude_file="$1"
			basename_xhosts_file=$(basename ${exclude_file})
                        ;;
                -h | --help )
                        usage
                        exit 0
                        ;;
                -V | --version )
                        echo -e "${yellow_color}[I] Script version is: ${bold_color}${version}${end_color}"
                        exit 0
                        ;;
                * )
			echo -e "${red_color}\n[X] One parameter or more does not exist.${end_color}"
                        usage
                        exit 1
        esac
        shift
done

root_user

# Checking if process already running
check_proc="$(ps -C "osic4MVS.sh" | grep -c "osic4MVS\.sh")"

if [[ ${check_proc} -gt "2" ]]; then
        echo -e "${red_color}[X] A process \"osic4MVS.sh\" is already running.${end_color}"
        exit 1
fi

# Valid input file?
if [[ -z ${hosts} ]] || [[ ! -s ${hosts} ]]; then
        echo -e "${red_color}[X] Input file \"${hosts}\" does not exist or is empty.${end_color}"
        echo "Please, try again."
        exit 1
fi

# Valid exclude file?
if [[ ${file_to_exclude} = "yes" ]]; then
        if [[ -z ${exclude_file} ]] || [[ ! -s ${exclude_file} ]]; then
                echo -e "${red_color}[X] Exclude file \"${exclude_file}\" does not exist or is empty.${end_color}"
                echo "Please, try again."
                exit 1
        fi
fi

logo

# Verifying if the OpenStack RC file exist
if [[ ! -z ${rc_file} ]] && [[ -s ${rc_file} ]]; then
	echo -e "${green_color}[V] The source file \"${rc_file}\" exists${end_color}"
else
	echo -e "${red_color}[X] The OpenStack RC file does not exist or is empty.${end_color}"
	echo -e "${purple_color}[I] This script can't be launched without it.${end_color}"
	exit 1
fi

# Verifying if the deployement script exist
if [[ ! -z ${deploy_script} ]] && [[ -s ${deploy_script} ]]; then
	echo -e "${green_color}[V] The deployment script \"${deploy_script}\" exists${end_color}"
else
	echo -e "${red_color}[X] The deployment script does not exist or is empty.${end_color}"
	echo -e "${purple_color}[I] This script can't be launched without it.${end_color}"
	exit 1
fi

# Verifying if the private SSH key exist
if [[ ! -z ${priv_key} ]] && [[ -s ${priv_key} ]]; then
	echo -e "${green_color}[V] The private SSH key \"${priv_key}\" exists${end_color}"
else
	echo -e "${red_color}[X] The private SSH key does not exist or is empty.${end_color}"
	echo -e "${purple_color}[I] This script can't be launched without it.${end_color}"
	exit 1
fi

# Verifying if the public SSH key name exist
if [[ -n ${pub_key_name} ]]; then
	echo -e "${green_color}[V] The public SSH key name \"${pub_key_name}\" is set${end_color}"
else
	echo -e "${red_color}[X] The public SSH key name is not set.${end_color}"
	echo -e "${purple_color}[I] This script can't be launched without it.${end_color}"
	exit 1
fi

check_internet
source "${rc_file}"

# Removing the old files
rm -rf hosts_converted.txt IPs.txt IPs_and_hostnames.txt uniq_IP_only.txt multiple_IPs_only.txt IPs_unsorted.txt ${hosts}_parsed ${exclude_file}_parsed 2>/dev/null

# Verifying if the instance is reachable
echo -n -e "\r                                                                                "
echo -n -e "${blue_color}\r[-] OpenStack accessibility check...${end_color}"
openstack_access=$(openstack server list > /dev/null 2>&1; echo $?)

if [[ ${openstack_access} == "1" ]]; then
        echo -e "${red_color}\r[X] The OpenStack RC file seems not valid.${end_color}             "
	exit 1
else
	echo -e "${green_color}\r[V] The OpenStack cloud seems reachable${end_color}              "
fi

# Running instances verification
echo -n -e "\r                                                                                "
echo -n -e "${blue_color}\r[-] Running instances verification...${end_color}"
running_instances=$(openstack server list | grep -Eoc "[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12}")

if [[ ${running_instances} -gt "0" ]] && [[ $(screen -ls | grep -Eoc "scan_[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}_[0-9]{1,6}") -gt "0" ]]; then
        echo -e "${red_color}\r[X] ${running_instances} instance(s) and screen session (s) already exist:${end_color}          "
        openstack server list
        echo -e "${red_color}[X] To delete it/them: source ${rc_file} && openstack server delete [ID or Name of instance]${end_color}"
        echo -e "${purple_color}[I] Don't forget to kill the associated screen session(s) below: screen -S [name] -X quit${end_color}"
        echo -e "--> ${bold_color}$(screen -ls | grep -Eo "scan_[0-9]{1,4}-[0-9]{1,2}-[0-9]{1,2}_[0-9]{1,6}")${end_color}"
        exit 1
elif [[ ${running_instances} -gt "0" ]]; then
        echo -e "${red_color}\r[X] ${running_instances} instance(s) already exist:${end_color}          "
        openstack server list
        echo -e "${red_color}[X] To delete it/them: source ${rc_file} && openstack server delete [ID or Name of instance]${end_color}"
        exit 1
else
	echo -e "${green_color}\r[V] No instance seems already running${end_color}              "
fi

#######################################
# Parsing the input and exclude files #
#######################################
num_hostnames_init=$(grep '[[:alnum:].-]' ${hosts} | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -vEc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')
num_ips_init=$(grep '[[:alnum:].-]' ${hosts} | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eoc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')

valid_ip(){
ip_to_check="$1"
if [[ $(ipcalc ${ip_to_check} | grep -c "INVALID") == "0" ]]; then
        is_valid="yes"
else
        is_valid="no"
fi
}

echo -n -e "\r                                                                                                                 "
echo -n -e "${blue_color}\r[-] Parsing the input file (DNS lookups, duplicate IPs, multiple hostnames and valid IPs)...${end_color}"

# Saving IPs first
if [[ ${num_ips_init} -gt "0" ]]; then
	ips_tab_init=($(grep '[[:alnum:].-]' ${hosts} | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eo '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*'))
        printf '%s\n' "${ips_tab_init[@]}" | while IFS=, read -r check_ip; do
                valid_ip "${check_ip}"
                if [[ "${is_valid}" == "yes" ]]; then
                        echo "${check_ip}" >> IPs.txt
                else
                        echo -n -e "${red_color}\r[X] \"${check_ip}\" is not a valid IPv4 address and/or subnet mask                                 \n${end_color}"
                fi
        done
fi

# First parsing to translate the hostnames to IPs
if [[ ${num_hostnames_init} != "0" ]]; then
        # Filtering on the hosts only
	hostnames_tab=($(grep '[[:alnum:].-]' ${hosts} | grep -Ev '^[[:punct:]]|[[:punct:]]$' | sed '/[]!"#\$%&'\''()\*+,:;<=>?@\[\\^_`{|}~]/d' | grep -vE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u))

        # Conversion to IPs
        printf '%s\n' "${hostnames_tab[@]}" | while IFS=, read -r host_to_convert; do
                search_ip=$(dig @${dns} ${host_to_convert} +short | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
                if [[ ${search_ip} != "" ]]; then
                        echo ${search_ip} ${host_to_convert} | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' >> hosts_converted.txt
                else
                        echo -n -e "\r                                                                                                                 "
                        echo -n -e "${red_color}\r[X] No IP found for hostname \"${host_to_convert}\".\n${end_color}"
                fi
        done
fi

# Second parsing to detect multiple IPs for the same hostname
if [[ -s hosts_converted.txt ]]; then
        ips_found="$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' hosts_converted.txt | sort -u | wc -l)"
        while IFS=, read -r line; do
                check_ips="$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)"

                # Filtering on the multiple IPs only
                if [[ ${check_ips} -gt "1" ]]; then
                        hostname=$(echo ${line} | grep -oE '[^ ]+$')
                        ips_list=$(echo ${line} | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
                        ips_tab=(${ips_list})
                        ips_loop="$(for index in "${!ips_tab[@]}"; do echo "${ips_tab[${index}]} ${hostname}"; done)"

                        echo "${ips_loop}" >> multiple_IPs.txt
                elif [[ ${check_ips} -eq "1" ]]; then
                        # Saving uniq IP
                        echo ${line} >> uniq_IPs.txt
                fi
        done < hosts_converted.txt

        if [[ -s uniq_IPs.txt ]]; then
                cat uniq_IPs.txt >> IPs_and_hostnames.txt
                rm -rf uniq_IPs.txt 2>/dev/null
        fi

        if [[ -s multiple_IPs.txt ]]; then
                cat multiple_IPs.txt >> IPs_and_hostnames.txt
                rm -rf multiple_IPs.txt 2>/dev/null
        fi

        # Third parsing to detect duplicate IPs and keep the multiple hostnames

        cat IPs_and_hostnames.txt | awk '/.+/ { \
                if (!($1 in ips_list)) { \
                value[++i] = $1 } ips_list[$1] = ips_list[$1] $2 "," } END { \
                for (j = 1; j <= i; j++) { \
                printf("%s %s\n%s", value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' > IPs_unsorted.txt
        rm -rf IPs_and_hostnames.txt
fi

if [[ ! -s IPs_unsorted.txt ]] && [[ ! -s IPs.txt ]]; then
	echo -n -e "${red_color}\r[X] No valid host found.\n${end_color}"
	exit 1
fi

if [[ -s IPs_unsorted.txt ]] && [[ -s IPs.txt ]]; then
        echo -n -e "\r                                                                                             "
        echo -n -e "${purple_color}\r[I] Valid host(s) to scan:\n${end_color}"
        cat IPs.txt >> IPs_unsorted.txt
        rm -rf IPs.txt
        sort -u IPs_unsorted.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts}_parsed
        rm -rf IPs_unsorted.txt
        cat ${hosts}_parsed
elif [[ -s IPs_unsorted.txt ]]; then
        echo -n -e "\r                                                                                             "
        echo -n -e "${purple_color}\r[I] Valid host(s) to scan:\n${end_color}"
        sort -u IPs_unsorted.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${hosts}_parsed
        rm -rf IPs_unsorted.txt
        cat ${hosts}_parsed
else
        echo -n -e "\r                                                                                             "
        echo -n -e "${purple_color}\r[I] Valid host(s) to scan:\n${end_color}"
        mv IPs.txt ${hosts}_parsed
        cat ${hosts}_parsed
fi

hosts_file_no_path="$(basename "$hosts")"
hosts_file="${hosts}_parsed"

if [[ ${exclude_file} != "" ]]; then
        echo -n -e "\r                                                                                                                 "
        echo -n -e "${blue_color}\r[-] Parsing the exclude file (valid IPv4 addresses ONLY)...${end_color}"
	num_xips_init=$(grep -Ev '^[[:punct:]]|[[:punct:]]$' ${exclude_file} | sed '/[]!"#\$%&'\''()\*+,\/:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eoc '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*')
        if [[ ${num_xips_init} -gt "0" ]]; then
		xips_tab_init=($(grep -Ev '^[[:punct:]]|[[:punct:]]$' ${exclude_file} | sed '/[]!"#\$%&'\''()\*+,\/:;<=>?@\[\\^_`{|}~]/d' | sort -u | grep -Eo '.*([0-9]{1,3}\.){3}[0-9]{1,3}.*'))
                printf '%s\n' "${xips_tab_init[@]}" | while IFS=, read -r check_ip; do
                        valid_ip "${check_ip}"
                        if [[ "${is_valid}" == "yes" ]]; then
                                echo "${check_ip}" >> xIPs.txt
                        else
                                echo -n -e "${red_color}\r[X] \"${check_ip}\" is not a valid IPv4 address and/or subnet mask to exclude                    \n${end_color}"
                        fi
                done
        fi
fi

if [[ -s xIPs.txt ]]; then
        echo -n -e "\r                                                                                            "
        echo -n -e "${purple_color}\r[I] Valid host(s) to exclude:\n${end_color}"
        sort -u xIPs.txt | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 > ${exclude_file}_parsed
        rm -rf xIPs.txt
        cat ${exclude_file}_parsed

fi

xhosts_file="${exclude_file}_parsed"

# Mandatory parameters
security_group="default"
image="Debian 10"
flavor="s1-8"
network="Ext-Net"

# Instance creation
echo -n -e "\r                                                                              "
echo -n -e "${blue_color}\r[-] Waiting for instance creation...${end_color}"
name="scan_$(date "+%Y-%m-%d_%H%M%S")"

if ! openstack server create ${name} --key-name "${pub_key_name}" --image "${image}" --flavor ${flavor} --user-data ${deploy_script} --network ${network} --security-group ${security_group} 1>/dev/null; then
        echo -e "${red_color}\r[X] ERROR! Thanks to verify your parameters or connectivity. The script is ended.${end_color}"
        exit 1
        else
                echo -e "${green_color}\r[V] Instance creation requested${end_color}                  "
fi

# Wait for instance to be up and running
echo -n -e "\r                                                                              "
echo -n -e "${blue_color}\r[-] Waiting for instance to be up and running...${end_color}"
host=""

# Wait for IPv4 address
while [[ -z ${host} ]]; do
        host=$(openstack server list -f table -c Networks | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
        sleep 0.5
done

# Removing the old offending RSA key in /root/.ssh/known_hosts
ssh-keygen -f "/root/.ssh/known_hosts" -R "${host}" > /dev/null 2>&1

# Wait for host to be online
echo -e "${green_color}\r[V] IPv4 found: ${host}${end_color}                                    "

while ! ping -W 1 -i 0.5 -c 1 "${host}" &>/dev/null; do
        echo -n -e "\r                                                                              "
        echo -n -e "${blue_color}\r[-] Host ${host} still offline...${end_color} - ${purple_color}$(date "+%Y/%m/%d %Hh%Mm%Ss")${end_color}"
        sleep 0.5
done

echo -e "${green_color}\r[V] Host ${host} recheable!${end_color}                                               "

# Wait for SSH port open
echo -n -e "\r                                                                              "
while ! nc -z -v -w 1 "${host}" 22 &>/dev/null; do
        echo -n -e "${blue_color}\r[-] Wait for SSH port open...${end_color} - ${purple_color}$(date "+%Y/%m/%d %Hh%Mm%Ss")${end_color}"
        sleep 1
done

echo -e "${green_color}\r[V] SSH port open!${end_color}                                                      "

# SSH command
ssh_command="ssh -q -i ${priv_key} debian@${host} -o HostKeyAlgorithms=+ssh-rsa -o CheckHostIP=no -o StrictHostKeyChecking=no -o ForwardX11=no"

# Hosts file(s) sent on the new instance
echo -n -e "\r                                                                              "
echo -n -e "${blue_color}\r[-] Sending the hosts file(s) on the new instance...${end_color}"

# Send the file(s) to scan
if [[ -s ${hosts_file} && -s ${xhosts_file} ]]; then
	${ssh_command} 'mkdir -p /tmp/osic4MVS/hosts && mkdir /tmp/osic4MVS/xhosts && chown -R debian:debian /tmp/osic4MVS/'
	scp -q -i ${priv_key} -o HostKeyAlgorithms=+ssh-rsa -o CheckHostIP=no -o StrictHostKeyChecking=no -o ForwardX11=no ${hosts_file} debian@${host}:/tmp/osic4MVS/hosts/${basename_hosts_file}
	scp -q -i ${priv_key} -o HostKeyAlgorithms=+ssh-rsa -o CheckHostIP=no -o StrictHostKeyChecking=no -o ForwardX11=no ${xhosts_file} debian@${host}:/tmp/osic4MVS/xhosts/${basename_xhosts_file}
else
	${ssh_command} 'mkdir -p /tmp/osic4MVS/hosts && chown -R debian:debian /tmp/osic4MVS/'
	scp -q -i ${priv_key} -o HostKeyAlgorithms=+ssh-rsa -o CheckHostIP=no -o StrictHostKeyChecking=no -o ForwardX11=no ${hosts_file} debian@${host}:/tmp/osic4MVS/hosts/${basename_hosts_file}
fi

if [[ $(${ssh_command} ls /tmp/osic4MVS/hosts | wc -l) -gt "0" ]]; then
	echo -e "${purple_color}\r[I] Hosts file(s) sent on the new instance.                                           ${end_color}"
else
	echo -e "${red_color}\r[X] ERROR! Thanks to verify your parameters or connectivity. No file(s) sent.${end_color}"
	openstack server delete "${name}"
	screen -S "${name}" -X quit
	exit 1
fi

echo -e "${purple_color}[I] Deployment of MassVulScan is starting on instance \"${name}\"${end_color}"

# MassVulScan deployment
package=""

for package in tar gcc make nc dig git wget locate xsltproc ipcalc nmap masscan; do
        echo -n -e "\r                                                                                         "
        while [[ ${package} =~ ^(tar|gcc|make|nc|dig|git|wget|locate|xsltproc|ipcalc|nmap)$ ]] && [[ $(${ssh_command} command -v ${package} ; echo $?) == "1" ]]; do
                echo -n -e "${blue_color}\r[-] APT update and upgrade of packages in progress (\"${package}\")...${end_color} - ${purple_color}$(date "+%Y/%m/%d %Hh%Mm%Ss")${end_color}"
                sleep 0.5
        done

        echo -n -e "\r                                                                                          "
        while [[ ${package} =~ ^(masscan)$ ]] && [[ $(${ssh_command} command -v ${package} ; echo $?) == "1" ]]; do
                echo -n -e "${blue_color}\r[-] Compiling and installing \"${package}\"...${end_color} - ${purple_color}$(date "+%Y/%m/%d %Hh%Mm%Ss")${end_color}"
                sleep 0.5
        done
done

echo -e "${green_color}\r[V] Deployment of MassVulScan is done${end_color}                                                    "

while [[ $(${ssh_command} 'ps -C "MassVulScan.sh" | grep -c "MassVulScan\.sh"') == "0" ]]; do
	echo -n -e "${blue_color}\r[-] We are starting the scan in few seconds...${end_color}"
done

# MassVulScan scanning phase

# Sending an email with the IPv4 address of the instance
# Set the variables before at the top of the script
if [[ ! -z ${smtp_server} ]] && [[ ! -z ${recipient} ]]; then
	email "Scan started from ${host}" && echo -e "${purple_color}\r[I] Informational message sent to ${recipient}${end_color}"
fi

# Reading the log file on the remote instance to follow the scan progression
screen -S "${name}" -d -m
screen -r "${name}" -X exec ${ssh_command} 'tail -f /var/log/cloud-init-output.log'
echo -e "${purple_color}\r[I] Follow the scan in live: ${bold_color}${blue_color}(sudo) screen -r ${name}${end_color}                "
echo -e "${purple_color}[I] To detach the screen session without killing it: ${bold_color}${blue_color}CTRL + A and D${end_color}"

echo -n -e "\r                                                                              "

while [[ $(${ssh_command} 'ps -C "MassVulScan.sh" | grep -c "MassVulScan\.sh"') -gt "0" ]]; do
	while [[ $(${ssh_command} 'ps -C "masscan" | grep -c "masscan"') -gt "0" ]]; do
		echo -n -e "${blue_color}\r[-] Masscan scanning in progress...${end_color} - ${purple_color}$(date "+%Y/%m/%d %Hh%Mm%Ss")${end_color}"
		sleep 1
	done

	while [[ $(${ssh_command} 'ps -C "nmap" | grep -c "nmap"') -gt "0" ]]; do
		echo -n -e "${blue_color}\r[-] Nmap scanning in progress...${end_color} - ${purple_color}$(date "+%Y/%m/%d %Hh%Mm%Ss")${end_color}    "
		sleep 1
	done
done

# Waiting the reports
echo -n -e "\r                                                                              "

if [[ $(${ssh_command} 'ps -C "MassVulScan.sh" | grep -c "MassVulScan\.sh"') == "0" && $(${ssh_command} 'if [[ -z "$(ls /tmp/MassVulScan/reports/)" ]]; then echo "Empty"; fi') == "Empty" ]]; then
        echo -e "${bold_color}${green_color}\r[V] The scan is finished but not reports are generated.${end_color}                                     "
else
		# Downloading the reports
		temp_dir="$(mktemp -d /tmp/temp-XXXXXXXX)"
		scp -q -i ${priv_key} -o HostKeyAlgorithms=+ssh-rsa -o CheckHostIP=no -o StrictHostKeyChecking=no -o ForwardX11=no debian@${host}:/tmp/MassVulScan/reports/* ${temp_dir}/
                reports="$(ls ${temp_dir}/)"
		
		# Saving reports
		cp -R "${temp_dir}"/* ./reports

                echo -e "${green_color}\r[V] The scan is finished, available reports (reports/):${end_color}                           "
		ls -1 "${temp_dir}"

		# Sending an email with the reports attached
		# Set the variables before at the top of the script
		if [[ ! -z ${smtp_server} ]] && [[ ! -z ${recipient} ]]; then
			for report in ${reports}; do
				email "Report: ${report}" "${temp_dir}/${report}"
			done
			echo -e "${purple_color}[I] Reports sent to ${recipient}${end_color}"
		fi
		
		rm -rf "${temp_dir}"
fi

# Deleting instance
echo -n -e "\r                                                                                              "
echo -n -e "${blue_color}\r[-] Deleting instance and screen session \"${name}\"...${end_color}"

openstack server delete "${name}"
screen -S "${name}" -X quit

# Set the variables before at the top of the script
# Sending an email with the report attached
if [[ ! -z ${smtp_server} ]] && [[ ! -z ${recipient} ]]; then
	email "Instance ${name} deleted"
fi

# Unset tenant access as a precaution
unset OS_AUTH_URL OS_IDENTITY_API_VERSION OS_PASSWORD OS_PROJECT_DOMAIN_NAME OS_REGION_NAME OS_TENANT_ID OS_TENANT_NAME OS_USERNAME OS_USER_DOMAIN_NAME

# Removing the files
rm -rf hosts_converted.txt IPs.txt IPs_and_hostnames.txt uniq_IP_only.txt multiple_IPs_only.txt IPs_unsorted.txt ${hosts}_parsed ${exclude_file}_parsed 2>/dev/null

echo -e "${green_color}\r[V] Instance deleted, bye.${end_color}                                                                                                           "
time_elapsed

exit 0
