#!/bin/bash

sudo ip link add br0 type bridge
sudo ip link add br1 type bridge
sudo ip link set veth3 master br0
sudo ip link set ens803f2 master br0
sudo ip link set veth5 master br1 
sudo ip link set ens803f3 master br1
sudo ip link set br0 up
sudo ip link set br1 up