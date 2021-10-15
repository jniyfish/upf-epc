#!/bin/bash

JSON=$1
P4INFO=$2

docker exec stratum sudo mkdir /etc/stratum/
docker exec stratum sudo mkdir /var/log/stratum/
docker cp ${JSON} stratum:/etc/stratum/dummy.json
docker cp ${P4INFO} stratum:/etc/stratum/pipeline_cfg.pb.txt

pid_stratum=$(sudo docker inspect -f '{{.State.Pid}}' stratum)
sudo ip link set ens803f2 netns $pid_stratum
sudo ip link set ens803f3 netns $pid_stratum


docker exec stratum sudo ip link set ens803f2 up
docker exec stratum sudo ip link set ens803f3 up

docker exec stratum sudo ip addr add 198.18.0.1/30 dev ens803f2 
docker exec stratum sudo ip addr add 198.19.0.1/30 dev ens803f3

docker exec stratum sudo apt install tcpdump -y
docker exec -it stratum bash

