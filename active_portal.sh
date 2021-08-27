#!/bin/bash



# GENERAL VARIABLES



IPTABLES="/sbin/iptables"

IP6TABLES="/sbin/ip6tables"

_subnets=("224.0.0.0/3" "169.254.0.0/16" "172.16.0.0/12" "192.0.2.0/24" "192.168.0.0/16" "0.0.0.0/8" "240.0.0.0/5")





# GENERAL CONFIGURATION

# Set the NAT/MANGLE tables chains ACCEPT

"$IPTABLES" -t nat -P PREROUTING ACCEPT

"$IPTABLES" -t nat -P OUTPUT ACCEPT

"$IPTABLES" -t nat -P POSTROUTING ACCEPT



"$IPTABLES" -t mangle -P PREROUTING ACCEPT

"$IPTABLES" -t mangle -P INPUT ACCEPT

"$IPTABLES" -t mangle -P FORWARD ACCEPT

"$IPTABLES" -t mangle -P OUTPUT ACCEPT

"$IPTABLES" -t mangle -P POSTROUTING ACCEPT



# Block everything first

"$IPTABLES" -P INPUT DROP

"$IPTABLES" -P FORWARD DROP

"$IPTABLES" -P OUTPUT DROP



# Setting up FORWARD chain

"$IPTABLES" -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT







#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



        #[*]raw



"$IPTABLES" -t raw -A PREROUTING -p tcp -m multiport --dports 80,443 --syn -j CT --notrack







#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



        #[*]mangle



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



# Drop all traffic from subnet ip

for _sub in "${_subnets[@]}" ; do

"$IPTABLES" -t mangle -A PREROUTING -s "$_sub" -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*spoofing* =DROP: "

"$IPTABLES" -t mangle -A PREROUTING -s "$_sub" -j DROP

done



# Drop no legitim lo/127.0.0.0

"$IPTABLES" -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*not-lo* =DROP: "

"$IPTABLES" -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP



# Drop incoming MSS values

"$IPTABLES" -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*mss* =>

"$IPTABLES" -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP









#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



        #[*]nat



# Target MASQUERADE

"$IPTABLES" -t nat -A POSTROUTING -s 192.168.1.21/24 -o ppp0 -j MASQUERADE









#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++





        #[*]filter



# Accept loopback traffic

"$IPTABLES" -A OUTPUT -o lo -j ACCEPT

"$IPTABLES" -A INPUT -i lo -j ACCEPT



# Accept all outbound ESTABLISHED,RELATED traffic

"$IPTABLES" -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT



# Accept all incoming ESTABLISHED traffic

"$IPTABLES" -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT









#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



#Drop no-syn

"$IPTABLES" -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]* ! SYN* =DROP: "

"$IPTABLES" -A INPUT -p tcp ! --syn -m state --state NEW -j DROP



# Drop all icmp ping request

"$IPTABLES" -A INPUT -p icmp -j DROP

"$IPTABLES" -A INPUT -i enp2s0 -p icmp -j DROP



# Limit connection on enp2s0

"$IPTABLES" -A INPUT -i enp2s0 -p tcp -m connlimit --connlimit-above 50 -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*LIMIT* =DROP: "

"$IPTABLES" -A INPUT -i enp2s0 -p tcp -m connlimit --connlimit-above 50 -j DROP



# Drop TTL values

"$IPTABLES" -A INPUT -s 1.2.3.4 -m ttl --ttl-lt 40 -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*TTL* =DROP: "

"$IPTABLES" -A INPUT -s 1.2.3.4 -m ttl --ttl-lt 40 -j DROP



# Prevent various scans type

# Create user-defined chain to Log all scans type

"$IPTABLES" -N NET-SCAN

"$IPTABLES" -A NET-SCAN -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*SCAN* =DROP: "

"$IPTABLES" -A NET-SCAN -j DROP



# Drop ports scanners and XMAS scans

"$IPTABLES" -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j NET-SCAN

"$IPTABLES" -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j NET-SCAN



# Blacklisting all port scanner

"$IPTABLES" -A INPUT -m recent --rcheck --seconds 86400 --name portscan --mask 255.255.255.255 --rsource -j NET-SCAN

"$IPTABLES" -A INPUT -m recent --remove --name portscan --mask 255.255.255.255 --rsource

"$IPTABLES" -A INPUT -p tcp -m multiport --dports 25,445,1433,3389 -m recent --set --name portscan --mask 255.255.255.255 --rsource -j NET-SCAN



# Drop incoming INVALID traffics

"$IPTABLES" -A INPUT -m conntrack --ctstate INVALID -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*INVALID* =DROP: "

"$IPTABLES" -A INPUT -m conntrack --ctstate INVALID -j DROP



# Drop and Log fragment traffic

"$IPTABLES" -A INPUT -f -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[WARN]*FRAGMENT* =DROP: "

"$IPTABLES" -A INPUT -f -j DROP



# Drop all in microsoft port

"$IPTABLES" -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP

"$IPTABLES" -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP



# Syn-flood protection

"$IPTABLES" -N SYN_FLOOD

"$IPTABLES" -A INPUT -p tcp --syn -j SYN_FLOOD

"$IPTABLES" -A SYN_FLOOD -m limit --limit 1/s --limit-burst 3 -j RETURN

"$IPTABLES" -A SYN_FLOOD -j DROP

"$IPTABLES" -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT

"$IPTABLES" -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix "[WARN]*SYN-FLOOD* =DROP: "

"$IPTABLES" -A INPUT -p icmp -j DROP

"$IPTABLES" -A OUTPUT -p icmp -j ACCEPT


# SynProxy

"$IPTABLES" -A INPUT -p tcp -m multiport --dports 80,443 -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460

"$IPTABLES" -A INPUT -p tcp -m multiport --dports 80,443 -m tcp -m conntrack --ctstate INVALID -j DROP









#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



# outbound [OUTPUT]

# Accept all outbound NEW,ESTABLISHED 53/tcp traffic

"$IPTABLES" -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[OUT]*DNS/TCP* =ACCEPT: "

"$IPTABLES" -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT



# Accept all outbound NEW,ESTABLISHED 53/udp traffic

"$IPTABLES" -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[OUT]*DNS/UDP* =ACCEPT: "

"$IPTABLES" -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT



# Accept all outbound NEW,ESTABLISHED 80/tcp traffic

"$IPTABLES" -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[OUT]*HTTP* =ACCEPT: "

"$IPTABLES" -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT



# Accept all outbound NEW,ESTABLISHED 443/tcp traffic

"$IPTABLES" -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[OUT]*HTTPS* =ACCEPT: "

"$IPTABLES" -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT



# *incoming [INPUT]

# Accept all incoming ESTABLISHED 53/tcp traffic

"$IPTABLES" -A INPUT -p tcp --dport 53 -m conntrack --ctstate ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[IN]*DNS/TCP* =ACCEPT: "

"$IPTABLES" -A INPUT -p tcp --dport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT



# Accept all incoming ESTABLISHED 80/tcp traffic

"$IPTABLES" -A INPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[IN]*HTTP* =ACCEPT: "

"$IPTABLES" -A INPUT -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT



# Accept all incoming ESTABLISHED 443/tcp traffic

"$IPTABLES" -A INPUT -p tcp --dport 443 -m conntrack --ctstate ESTABLISHED -m limit --limit 5/m --limit-burst 10 -j LOG --log-prefix "[IN]*HTTPS* =ACCEPT: "

"$IPTABLES" -A INPUT -p tcp --dport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT



exit 0





