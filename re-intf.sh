#!/bin/bash

sudo ip link set veth2 down
sudo ip link set veth2 name ens803f2
sudo ip link set ens803f2 up

sudo ip link set veth4 down
sudo ip link set veth4 name ens803f3
sudo ip link set ens803f3 down
