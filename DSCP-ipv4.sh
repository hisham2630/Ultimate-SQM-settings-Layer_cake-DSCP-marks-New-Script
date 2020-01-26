#!/bin/bash -x
IPT="iptables"
##########
#Veth start
##########
WANIF="pppoe-wan" #wan interface

tc qdisc add dev wlan0 root mq #setup multi queue for wifi device
## set up veth devices to handle inbound and outbound traffic
ip link show | grep veth0 || ip link add type veth

## get new veth interfaces up
ip link set veth0 up
ip link set veth1 up

## trun on promisc mode,sometimes it's needed to make bridge work
ip link set veth1 promisc on

## add veth1 to bridge
brctl addif br-lan veth1

## just to make sure there's nothing inside this table
ip rule del priority 100
ip route flush table 100

#########
#Veth end
#########
##ipset for streaming sites.they are being filled by dnsmasq
ipset create streaming hash:ip
ipset create usrcdn hash:ip
ipset create bulk hash:ip
ipset create latsens hash:ip


## add routing for veth0 this will handle all traffic
ip route add default dev veth0 table 100
ip rule add iif $WANIF table 100 priority 100

$IPT -t mangle -N dscp_mark > /dev/null 2>&1
$IPT -t mangle -F dscp_mark
## check if POSTROUTING already exits then jumps to our tables if not, add them

$IPT -t mangle -L POSTROUTING -n | grep dscp_mark || $IPT -t mangle -A POSTROUTING -j dscp_mark

iptmark(){
    $IPT -t mangle -A dscp_mark "$@"
}

# Example How to limit video to 200ko/s in case you're on quota ( 4G/LTE )
# first clean all : 
#iptables -F forwarding_rule
#iptables  -A forwarding_rule -m set --match-set vidstream src -m hashlimit --hashlimit-mode srcip,dstip --hashlimit-name "videolimit" --hashlimit-above 200kb/s -j DROP
#iptables  -A forwarding_rule -s 64.18.0.0/20,64.233.160.0/19,66.102.0.0/20,66.249.80.0/20,72.14.192.0/18,74.125.0.0/16,173.194.0.0/16,207.126.144.0/20,209.85.128.0/17,216.58.208.0/20,216.239.32.0/19 -m hashlimit --hashlimit-mode srcip,dstip --hashlimit-name "videolimit" --hashlimit-above 200kb/s -j DROP

## start by washing the dscp to CS0

iptmark -j DSCP --set-dscp 0

#A robust 2 rules to detect realtime traffic

# mark connections that go over 115 packets per second, not prioritized
iptmark -p udp -m hashlimit --hashlimit-name udp_high_prio --hashlimit-above 115/sec --hashlimit-burst 50 --hashlimit-mode srcip,srcport,dstip,dstport -j CONNMARK --set-mark 0x55 -m comment --comment "connmark for udp"

# unmarked UDP streams with small packets get CS6
iptmark -p udp -m connmark ! --mark 0x55 -m multiport ! --ports 22,25,53,67,68,123,143,161,162,514,5353,80,443,8080,60001 -m connbytes --connbytes 0:940 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class CS6 -m comment --comment "small udp connection gets CS6"

#large udp streams like video call get AF41
iptmark -p udp -m connmark ! --mark 0x55 -m multiport ! --ports 22,25,53,67,68,123,143,161,162,514,5353,80,443,8080,60001 -m connbytes --connbytes 940:1500 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class AF41 -m comment --comment "large udp connection gets AF41"

########################################
# Latency Sensitive (gaming/voip)
########################################
##ICMP, to prioritize pings
iptmark -p icmp -j DSCP --set-dscp-class CS5 -m comment --comment "ICMP-pings"

#DNS traffic both udp and tcp
iptmark -p udp -m multiport --port 53,5353,8888 -j DSCP --set-dscp-class CS5 -m comment --comment "DNS udp"
iptmark -p tcp -m multiport --port 53,5353,8888 -j DSCP --set-dscp-class CS5 -m comment --comment "DNS tcp"

#NTP
iptmark -p udp -m multiport --port 123 -j DSCP --set-dscp-class CS6 -m comment --comment "NTP udp"

#High priority ipset, i use for pubgM
iptmark ! -p tcp -m set --match-set latsens src,dst -j DSCP --set-dscp-class CS6 -m comment --comment "latency sensitive ipset" ## set dscp tag for Latency Sensitive (latsens) ipset,udp

iptmark -p tcp -m set --match-set latsens src,dst -j DSCP --set-dscp-class CS5 -m comment --comment "latency sensitive ipset" ## set dscp tag for Latency Sensitive (latsens) ipset

########
##Browsing
########
## medium priority for browsing
iptmark -p tcp -m multiport --ports 80,443,8080 -j DSCP --set-dscp-class CS3 -m comment --comment "Browsing at CS3"

##################
#TCP SYN,ACK flows
##################
#Make sure ACK,SYN packets get priority (to avoid upload speed limiting our download speed)
iptmark -p tcp --tcp-flags ALL ACK -m length --length :128 -j DSCP --set-dscp-class CS3
iptmark -p tcp --tcp-flags ALL SYN -m length --length :666 -j DSCP --set-dscp-class CS3

#Small packet is probably interactive or flow control
iptmark -m dscp ! --dscp  24 -m dscp ! --dscp  18 -m dscp ! --dscp  34 -m dscp ! --dscp  40 -m dscp ! --dscp  48 -m length --length 0:500 -j DSCP --set-dscp-class CS3

#Small packet connections: multi purpose (don't harm since not maxed out)
iptmark -m dscp ! --dscp  24 -m dscp ! --dscp  18 -m dscp ! --dscp  34 -m dscp ! --dscp  40 -m dscp ! --dscp  48 -m connbytes --connbytes 0:250 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class CS3


########################################
# Streaming Media (videos/audios)
########################################
#Known video streams sites like netflix
iptmark -m set --match-set streaming src,dst -j DSCP --set-dscp-class AF41 -m comment --comment "video audio stream ipset"

# some iptv provider's use this port
iptmark -p tcp -m multiport --ports 1935,9982 -j DSCP --set-dscp-class AF41 -m comment --comment "some iptv streaming service"

#known usrcdn like google or akamai

iptmark -m set --match-set usrcdn src,dst -j DSCP --set-dscp-class AF21 -m comment --comment "usrcdn ipset"

#########################################
# Background Traffic (Bulk/file transfer)
#########################################
#bulk traffic ipset, like windows udates and steam updates/downloads
iptmark -p tcp -m set --match-set bulk src,dst -j DSCP --set-dscp-class CS1 -m comment --comment "bulk traffic ipset"
iptmark -p udp -m set --match-set bulk src,dst -j DSCP --set-dscp-class CS1 -m comment --comment "bulk traffic ipset"
iptmark -p tcp -m connbytes --connbytes 350000: --connbytes-dir both --connbytes-mode bytes -m dscp --dscp-class CS0 -j DSCP --set-dscp-class CS1 -m comment --comment "Downgrade CS0 to CS1 for bulk tcp traffic"
iptmark -p tcp -m connbytes --connbytes 350000: --connbytes-dir both --connbytes-mode bytes -m dscp --dscp-class CS3 -j DSCP --set-dscp-class CS1 -m comment --comment "Downgrade CS3 to CS1 for bulk tcp traffic"
iptmark -p udp -m multiport --port 60001 -j DSCP --set-dscp-class CS1 -m comment --comment "bulk torrent port UDP"


#tcpdump rule, copy and paste this rule into terminal, this rule is used to capture realtime traffic, you can change ip to what you like
#tcpdump -i br-lan host 192.168.1.126 and udp and portrange 1-65535 and !port 53 and ! port 80 and ! port 443 -vv -X -w /root/cap-name.p
