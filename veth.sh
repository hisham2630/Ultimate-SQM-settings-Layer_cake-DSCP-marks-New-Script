#!/bin/bash -x
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
