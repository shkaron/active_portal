#!/bin/bash

# General variables

IPTABLES="/sbin/iptables"

################

_subnets=("224.0.0.0/3" "169.254.0.0/16" "172.16.0.0/12" "192.0.2.0/24" "192.168.0.0/16" "0.0.0.0/8" "240.0.0.0/5")

HEIGHT=15
WIDTH=40
CHOICE_HEIGHT=4
BACKTITLE="HXsha.sh"
TITLE="HXsha MENU"
MENU="Choose one of the following options:"

OPTIONS=(1 "Apply defaults iptables configurations rules"
         2 "Apply kernel settings"
         3 "Delete all iptables rules"
	 4 "Start|Enable iptables.service"
	 5 "Show ESTABLISHED traffic "
	 6 "Show iptables.service status"
	 7 "Stop iptables.service")

CHOICE=$(dialog --clear \
                --backtitle "$BACKTITLE" \
                --title "$TITLE" \
                --menu "$MENU" \
                $HEIGHT $WIDTH $CHOICE_HEIGHT \
                "${OPTIONS[@]}" \
                2>&1 >/dev/tty)

clear
case $CHOICE in

        1)

		#LOG

		"$IPTABLES" -N LOG_ACCEPT # input traffic log
		"$IPTABLES" -A LOG_ACCEPT -j LOG -m limit --limit 3/m --limit-burst 8 --log-prefix "ACCEPT "
		"$IPTABLES" -A LOG_ACCEPT -j ACCEPT

		"$IPTABLES" -N LOG_REJECT # reject traffic log
		"$IPTABLES" -A LOG_REJECT -j LOG -m limit --limit 3/m --limit-burst 8 --log-prefix "REJECT "
		"$IPTABLES" -A LOG_REJECT -p tcp -j REJECT --reject-with tcp-reset
		"$IPTABLES" -A LOG_REJECT -j REJECT

		"$IPTABLES" -N LOG_DROP # drop traffic log
		"$IPTABLES" -A LOG_DROP -j LOG -m limit --limit 3/m --limit-burst 8 --log-prefix "DROP "
		"$IPTABLES" -A LOG_DROP -j DROP

		# Append log configuration
		#
		#
		#
		#
		# Set the NAT/MANGLE tables chains ACCEPT

		"$IPTABLES" -t nat -P PREROUTING ACCEPT
		"$IPTABLES" -t nat -P OUTPUT ACCEPT
		"$IPTABLES" -t nat  -P POSTROUTING ACCEPT

		"$IPTABLES" -t mangle -P PREROUTING ACCEPT
		"$IPTABLES" -t mangle  -P INPUT ACCEPT
		"$IPTABLES" -t mangle -P FORWARD ACCEPT
		"$IPTABLES" -t mangle -P OUTPUT ACCEPT
		"$IPTABLES" -t mangle -P POSTROUTING ACCEPT


		# Block everything first

		"$IPTABLES" -P INPUT DROP
		"$IPTABLES" -P FORWARD DROP
		"$IPTABLES" -P OUTPUT DROP


		## ICMP
		# Drop any other ICMP traffic.

		"$IPTABLES" -A INPUT -p icmp -j REJECT --reject-with icmp-proto-unreachable
		"$IPTABLES" -A OUTPUT -p icmp -j REJECT --reject-with icmp-proto-unreachable
		"$IPTABLES" -A FORWARD -p icmp -j REJECT --reject-with icmp-proto-unreachable

		# Drop all fragmented ICMP packets

		"$IPTABLES" -A INPUT -p icmp --fragment -j REJECT --reject-with icmp-proto-unreachable
		"$IPTABLES" -A OUTPUT -p icmp --fragment -j REJECT --reject-with icmp-proto-unreachable
		"$IPTABLES" -A FORWARD -p icmp --fragment -j REJECT --reject-with icmp-proto-unreachable

		# Allow RELATED,ESTABLISHED traffic

		"$IPTABLES" -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		"$IPTABLES" -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

		# Allow lo traffic

		"$IPTABLES" -A INPUT -i lo -j ACCEPT
		"$IPTABLES" -A OUTPUT -o lo -j ACCEPT

		# Drop all INVALID traffic

		"$IPTABLES" -A INPUT -m conntrack --ctstate INVALID -j DROP
		"$IPTABLES" -A OUTPUT -m conntrack --ctstate INVALID -j DROP

		# Microsoft

		"$IPTABLES" -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j LOG_DROP
		"$IPTABLES" -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j LOG_DROP

		# Blacklisting port scanner

		"$IPTABLES" -A INPUT -m recent --rcheck --seconds 86400 --name portscan --mask 255.255.255.255 --rsource -j DROP
		"$IPTABLES" -A INPUT -m recent --remove --name portscan --mask 255.255.255.255 --rsource
		"$IPTABLES" -A INPUT -p tcp -m multiport --dports 25,445,1433,3389 -m recent --set --name portscan --mask 255.255.255.255 --rsource -j DROP

		# SYN FLOOD

		"$IPTABLES" -N SYN_FLOOD

		"$IPTABLES" -A INPUT -p tcp --syn -j SYN_FLOOD
		"$IPTABLES" -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN
		"$IPTABLES" -A SYN_FLOOD -j DROP

		"$IPTABLES" -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT

		"$IPTABLES" -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
		"$IPTABLES" -A INPUT -p icmp -j DROP

		"$IPTABLES" -A OUTPUT -p icmp -j ACCEPT

		# TTL values

		"$IPTABLES" -A INPUT -s 1.2.3.4 -m ttl --ttl-lt 40 -j REJECT

		# SYNPROXY

		"$IPTABLES" -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
		"$IPTABLES" -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
		"$IPTABLES" -A INPUT -m conntrack --ctstate INVALID -j DROP

		# Drop no SYN traffic

		"$IPTABLES" -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

		# Drop traffic avoid subnets (spoofing)

        	for _sub in "${_subnets[@]}" ; do
                	"$IPTABLES" -t mangle -A PREROUTING -s "$_sub" -j DROP
        	done

		# Drop not legitim lo traffic

		"$IPTABLES" -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP

		# Syn scans

		"$IPTABLES" -A INPUT -p tcp -m recent --update --rsource --seconds 60 --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
		"$IPTABLES" -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset

		# UDP scans

		"$IPTABLES" -A INPUT -p udp -m recent --update --rsource --seconds 60 --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable
		"$IPTABLES" -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
		"$IPTABLES" -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable

		# Port scanner

		"$IPTABLES" -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP
		"$IPTABLES" -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP

		# Drop pollution avoid WAN

		"$IPTABLES" -t mangle -A PREROUTING -i ppp0 -m addrtype --limit-iface-in ! --src-type UNICAST -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -i ppp0 -m addrtype --limit-iface-in --dst-type UNSPEC -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -i ppp0 -m addrtype --limit-iface-in --dst-type BROADCAST -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -i ppp0 -m addrtype --limit-iface-in --dst-type MULTICAST -j DROP
		"$IPTABLES" -t mangle -A POSTROUTING -o ppp0 -m addrtype --limit-iface-out ! --dst-type UNICAST -j DROP
		"$IPTABLES" -t mangle -A POSTROUTING -o ppp0 -m addrtype --limit-iface-out --src-type UNSPEC -j DROP
		"$IPTABLES" -t mangle -A POSTROUTING -o ppp0 -m addrtype --limit-iface-out --src-type BROADCAST -j DROP
		"$IPTABLES" -t mangle -A POSTROUTING -o ppp0 -m addrtype --limit-iface-out --src-type MULTICAST -j DROP

		# Drop bogus TCP flags

		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
		"$IPTABLES" -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

		# Drop incoming MSS values

		"$IPTABLES" -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

		# Allow 53,80,443 ports

		"$IPTABLES" -A INPUT -p tcp -m multiport --dports 53,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		"$IPTABLES"  -A OUTPUT -p tcp -m multiport --dports 53,80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

	;;

	2)
		sysctl -p

	;;

	3)

		iptables -F
		iptables -X
		iptables -t nat -F
		iptables -t nat -X
		iptables -t mangle -F
		iptables -t mangle -X
		iptables -t raw -F
		iptables -t raw -X
		iptables -t security -F
		iptables -t security -X
		iptables -P INPUT ACCEPT
		iptables -P FORWARD ACCEPT
		iptables -P OUTPUT ACCEPT
	;;

	4)

		systemctl start iptables.service
		systemctl enable iptables.service

	;;

	5)

		netstat | grep "ESTABLISHED"

	;;

	6)

		systemctl status iptables service

	;;

	7)

		systemctl stop iptables.service
	;;

esac

exit 0
