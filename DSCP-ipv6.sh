#!/bin/bash -x
IPT="iptables"
IPT6="ip6tables"
###########
#Veth start
###########
WANIF="pppoe-wan" #wan interface name

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

## add routing for veth0 this will handle all traffic
ip route add default dev veth0 table 100
ip rule add iif $WANIF table 100 priority 100
#########
#Veth end
#########

##ipset for streaming sites.they are being filled by dnsmasq
ipset create streaming hash:ip
ipset create streaming6 hash:ip family inet6

ipset create usrcdn hash:ip
ipset create usrcdn6 hash:ip family inet6

ipset create bulk hash:ip
ipset create bulk6 hash:ip family inet6

ipset create latsens hash:ip
ipset create latsens6 hash:ip family inet6

$IPT -t mangle -N dscp_mark > /dev/null 2>&1
$IPT6 -t mangle -N dscp_mark > /dev/null 2>&1

$IPT -t mangle -F dscp_mark
$IPT6 -t mangle -F dscp_mark

## check if POSTROUTING already exits then jumps to our tables if not, add them

$IPT -t mangle -L POSTROUTING -n | grep dscp_mark || $IPT -t mangle -A POSTROUTING -j dscp_mark

$IPT6 -t mangle -L POSTROUTING -n | grep dscp_mark || $IPT6 -t mangle -A POSTROUTING -j dscp_mark

iptmark() {
    $IPT -t mangle -A dscp_mark "$@"
}

ipt6mark() {
    $IPT6 -t mangle -A dscp_mark "$@"
}

## start by washing the dscp to CS0

iptmark -j DSCP --set-dscp 0
ipt6mark -j DSCP --set-dscp 0

#A robust 2 rules to detect realtime traffic

# mark connections that go over 115 packets per second, not prioritized
iptmark -p udp -m hashlimit --hashlimit-name udp_high_prio --hashlimit-above 115/sec --hashlimit-burst 50 --hashlimit-mode srcip,srcport,dstip,dstport -j CONNMARK --set-mark 0x55 -m comment --comment "connmark for udp"

ipt6mark -p udp -m hashlimit --hashlimit-name udp_high_prio --hashlimit-above 115/sec --hashlimit-burst 50 --hashlimit-mode srcip,srcport,dstip,dstport -j CONNMARK --set-mark 0x55 -m comment --comment "connmark for udp6"

# unmarked UDP streams with small packets get CS6
iptmark -p udp -m connmark ! --mark 0x55 -m multiport ! --ports 22,25,53,67,68,123,143,161,162,514,5353,80,443,8080,60001 -m connbytes --connbytes 0:940 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class CS6 -m comment --comment "small udp connection gets CS6"

ipt6mark -p udp -m connmark ! --mark 0x55 -m multiport ! --ports 22,25,53,67,68,123,143,161,162,514,5353,80,443,8080,60001 -m connbytes --connbytes 0:940 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class CS6 -m comment --comment "small udp6 connection gets CS6"

#large udp streams like video call get AF41
iptmark -p udp -m connmark ! --mark 0x55 -m multiport ! --ports 22,25,53,67,68,123,143,161,162,514,5353,80,443,8080,60001 -m connbytes --connbytes 940:1500 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class AF41 -m comment --comment "large udp connection gets AF41"

ipt6mark -p udp -m connmark ! --mark 0x55 -m multiport ! --ports 22,25,53,67,68,123,143,161,162,514,5353,80,443,8080,60001 -m connbytes --connbytes 940:1500 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class AF41 -m comment --comment "large udp6 connection gets AF41"

########################################
# Latency Sensitive (gaming/voip)
########################################
##ICMP, to prioritize pings
iptmark -p icmp -j DSCP --set-dscp-class CS5 -m comment --comment "ICMP-pings"
ipt6mark -p icmp -j DSCP --set-dscp-class CS5 -m comment --comment "ICMP6-pings"

#DNS traffic both udp and tcp
iptmark -p udp -m multiport --port 53,5353,8888 -j DSCP --set-dscp-class CS5 -m comment --comment "DNS udp"
ipt6mark -p udp -m multiport --port 53,5353,8888 -j DSCP --set-dscp-class CS5 -m comment --comment "DNS udp6"

iptmark -p tcp -m multiport --port 53,5353,8888 -j DSCP --set-dscp-class CS5 -m comment --comment "DNS tcp"
ipt6mark -p tcp -m multiport --port 53,5353,8888 -j DSCP --set-dscp-class CS5 -m comment --comment "DNS tcp6"

#NTP
iptmark -p udp -m multiport --port 123 -j DSCP --set-dscp-class CS6 -m comment --comment "NTP udp"
ipt6mark -p udp -m multiport --port 123 -j DSCP --set-dscp-class CS6 -m comment --comment "NTP6 udp"

#High priority ipset, i use for pubgM
iptmark ! -p tcp -m set --match-set latsens src,dst -j DSCP --set-dscp-class CS6 -m comment --comment "latency sensitive ipset" ## set dscp tag for Latency Sensitive (latsens) ipset,udp
ipt6mark ! -p tcp -m set --match-set latsens6 src,dst -j DSCP --set-dscp-class CS6 -m comment --comment "latency sensitive ipset6" ## set dscp tag for Latency Sensitive (latsens) ipset,udp

iptmark -p tcp -m set --match-set latsens src,dst -j DSCP --set-dscp-class CS5 -m comment --comment "latency sensitive ipset" ## set dscp tag for Latency Sensitive (latsens) ipset
ipt6mark -p tcp -m set --match-set latsens6 src,dst -j DSCP --set-dscp-class CS5 -m comment --comment "latency sensitive ipset6" ## set dscp tag for Latency Sensitive (latsens) ipset

###########
##Browsing
###########
## medium priority for browsing
iptmark -p tcp -m multiport --ports 80,443,8080 -j DSCP --set-dscp-class CS3 -m comment --comment "Browsing at CS3"

ipt6mark -p tcp -m multiport --ports 80,443,8080 -j DSCP --set-dscp-class CS3 -m comment --comment "Browsing6 at CS3"
##################
#TCP SYN,ACK flows
##################
#Make sure ACK,SYN packets get priority (to avoid upload speed limiting our download speed)
iptmark -p tcp --tcp-flags ALL ACK -m length --length :128 -j DSCP --set-dscp-class CS3
ipt6mark -p tcp --tcp-flags ALL ACK -m length --length :128 -j DSCP --set-dscp-class CS3

iptmark -p tcp --tcp-flags ALL SYN -m length --length :666 -j DSCP --set-dscp-class CS3
ipt6mark -p tcp --tcp-flags ALL SYN -m length --length :666 -j DSCP --set-dscp-class CS3

#Small packet is probably interactive or flow control
iptmark -m dscp ! --dscp  24 -m dscp ! --dscp  18 -m dscp ! --dscp  34 -m dscp ! --dscp  40 -m dscp ! --dscp  48 -m length --length 0:500 -j DSCP --set-dscp-class CS3
ipt6mark -m dscp ! --dscp  24 -m dscp ! --dscp  18 -m dscp ! --dscp  34 -m dscp ! --dscp  40 -m dscp ! --dscp  48 -m length --length 0:500 -j DSCP --set-dscp-class CS3

#Small packet connections: multi purpose (don't harm since not maxed out)
iptmark -m dscp ! --dscp  24 -m dscp ! --dscp  18 -m dscp ! --dscp  34 -m dscp ! --dscp  40 -m dscp ! --dscp  48 -m connbytes --connbytes 0:250 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class CS3
ipt6mark -m dscp ! --dscp  24 -m dscp ! --dscp  18 -m dscp ! --dscp  34 -m dscp ! --dscp  40 -m dscp ! --dscp  48 -m connbytes --connbytes 0:250 --connbytes-dir both --connbytes-mode avgpkt -j DSCP --set-dscp-class CS3

########################################
# Streaming Media (videos/audios)
########################################
#Known video streams sites like netflix
iptmark -m set --match-set streaming src,dst -j DSCP --set-dscp-class AF41 -m comment --comment "video audio stream ipset"
ipt6mark -m set --match-set streaming6 src,dst -j DSCP --set-dscp-class AF41 -m comment --comment "video audio stream ipset6"

# some iptv provider's use this port
iptmark -p tcp -m multiport --ports 1935,9982 -j DSCP --set-dscp-class AF41 -m comment --comment "some iptv streaming service"
ipt6mark -p tcp -m multiport --ports 1935,9982 -j DSCP --set-dscp-class AF41 -m comment --comment "some iptv streaming service6"

#known usrcdn like google or akamai
iptmark -m set --match-set usrcdn src,dst -j DSCP --set-dscp-class AF21 -m comment --comment "usrcdn ipset"
ipt6mark -m set --match-set usrcdn6 src,dst -j DSCP --set-dscp-class AF21 -m comment --comment "usrcdn ipset6"

#########################################
# Background Traffic (Bulk/file transfer)
#########################################
#bulk traffic ipset, like windows udates and steam updates/downloads
iptmark -p tcp -m set --match-set bulk src,dst -j DSCP --set-dscp-class CS1 -m comment --comment "bulk traffic ipset"
ipt6mark -p tcp -m set --match-set bulk6 src,dst -j DSCP --set-dscp-class CS1 -m comment --comment "bulk traffic ipset6"

iptmark -p udp -m set --match-set bulk src,dst -j DSCP --set-dscp-class CS1 -m comment --comment "bulk traffic ipset"
ipt6mark -p udp -m set --match-set bulk6 src,dst -j DSCP --set-dscp-class CS1 -m comment --comment "bulk traffic ipset6"

iptmark -p tcp -m connbytes --connbytes 350000: --connbytes-dir both --connbytes-mode bytes -m dscp --dscp-class CS0 -j DSCP --set-dscp-class CS1 -m comment --comment "Downgrade CS0 to CS1 for bulk tcp traffic"
ipt6mark -p tcp -m connbytes --connbytes 350000: --connbytes-dir both --connbytes-mode bytes -m dscp --dscp-class CS0 -j DSCP --set-dscp-class CS1 -m comment --comment "Downgrade CS0 to CS1 for bulk tcp traffic6"

iptmark -p tcp -m connbytes --connbytes 350000: --connbytes-dir both --connbytes-mode bytes -m dscp --dscp-class CS3 -j DSCP --set-dscp-class CS1 -m comment --comment "Downgrade CS3 to CS1 for bulk tcp traffic"
ipt6mark -p tcp -m connbytes --connbytes 350000: --connbytes-dir both --connbytes-mode bytes -m dscp --dscp-class CS3 -j DSCP --set-dscp-class CS1 -m comment --comment "Downgrade CS3 to CS1 for bulk tcp traffic6"

iptmark -p udp -m multiport --port 60001 -j DSCP --set-dscp-class CS1 -m comment --comment "bulk torrent port UDP"
ipt6mark -p udp -m multiport --port 60001 -j DSCP --set-dscp-class CS1 -m comment --comment "bulk torrent port UDP6"

#tcpdump rule, copy and paste this rule into terminal, this rule is used to capture realtime traffic, you can change ip to what you like
#tcpdump -i br-lan host 192.168.1.126 and udp and portrange 1-65535 and !port 53
