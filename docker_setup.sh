#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2019 Intel Corporation

set -e
# TCP port of bess/web monitor
gui_port=8033
bessd_port=10514
metrics_port=8333

# Driver options. Choose any one of the three
#
# "dpdk" set as default
# "af_xdp" uses AF_XDP sockets via DPDK's vdev for pkt I/O. This version is non-zc version. ZC version still needs to be evaluated.
# "af_packet" uses AF_PACKET sockets via DPDK's vdev for pkt I/O.
# "sim" uses Source() modules to simulate traffic generation
#mode="dpdk"
#mode="af_xdp"
mode="af_packet"
#mode="sim"

# Gateway interface(s)
#
# In the order of ("s1u" "sgi")
ifaces=("ens803f2" "ens803f3")

# Static IP addresses of gateway interface(s) in cidr format
#
# In the order of (s1u sgi)
ipaddrs=(198.18.0.1/30 198.19.0.1/30)

# MAC addresses of gateway interface(s)
#
# In the order of (s1u sgi)
macaddrs=(00:15:4d:13:63:5c 00:15:4d:13:63:5d)

# Static IP addresses of the neighbors of gateway interface(s)
#
# In the order of (n-s1u n-sgi)
nhipaddrs=(198.18.0.2 198.19.0.2)

# Static MAC addresses of the neighbors of gateway interface(s)
#
# In the order of (n-s1u n-sgi)
nhmacaddrs=(88:00:66:99:5b:47 7c:d3:0a:90:83:c1)

# IPv4 route table entries in cidr format per port
#
# In the order of ("{r-s1u}" "{r-sgi}")
routes=("198.18.0.0/30" "0.0.0.0/0")

num_ifaces=${#ifaces[@]}
num_ipaddrs=${#ipaddrs[@]}

# Assign IP address(es) of gateway interface(s) within the network namespace

# Set up mirror links to communicate with the kernel
#
# These vdev interfaces are used for ARP + ICMP updates.
# ARP/ICMP requests are sent via the vdev interface to the kernel.
# ARP/ICMP responses are captured and relayed out of the dpdk ports.
# Stop previous instances of bess* before restarting
docker stop pause bess-pfcpiface || true
docker rm -f pause bess-pfcpiface || true
sudo rm -rf /var/run/netns/pause

# Build
make docker-build

if [ "$mode" == 'dpdk' ]; then
	DEVICES=${DEVICES:-'--device=/dev/vfio/48 --device=/dev/vfio/49 --device=/dev/vfio/vfio'}
	PRIVS='--cap-add IPC_LOCK'

elif [ "$mode" == 'af_xdp' ]; then
	PRIVS='--privileged'

elif [ "$mode" == 'af_packet' ]; then
	PRIVS='--cap-add IPC_LOCK'
fi

# Run pause
docker run --name pause -td --restart unless-stopped \
	-p $bessd_port:$bessd_port \
	-p $gui_port:$gui_port \
	-p $metrics_port:$metrics_port \
	--hostname $(hostname) \
	k8s.gcr.io/pause

# Emulate CNI + init container
sudo mkdir -p /var/run/netns
sandbox=$(docker inspect --format='{{.NetworkSettings.SandboxKey}}' pause)
sudo ln -s "$sandbox" /var/run/netns/pause

case $mode in
"dpdk" | "sim") setup_mirror_links ;;
"af_xdp" | "af_packet")
	# Make sure that kernel does not send back icmp dest unreachable msg(s)
	sudo ip netns exec pause iptables -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP
	;;
*) ;;

esac




# Run bess-pfcpiface depending on mode type
docker run --name bess-pfcpiface -td --restart on-failure \
	--net container:pause \
	-v "$PWD/conf/upf.json":/conf/upf.json \
	upf-epc-pfcpiface:"$(<VERSION)" \
	-config /conf/upf.json



