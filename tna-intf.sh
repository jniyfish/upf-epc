#!/bin/bash

sudo ip link set ens803f2 down
sudo ip link set ens803f2 name veth2
sudo ip link set veth2 up

sudo ip link set ens803f3 down
sudo ip link set ens803f3 name veth4
sudo ip link set veth4 up
