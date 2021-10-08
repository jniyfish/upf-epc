#!/bin/bash


docker exec stratum sudo mkdir /etc/stratum/
docker exec stratum sudo mkdir /var/log/stratum/
docker cp ./conf/p4/bin/up4.txt stratum:/etc/stratum/pipeline_cfg.pb.txt
#docker cp ./conf/p4/bin/p4info.txt stratum:/etc/stratum/pipeline_cfg.pb.txt
docker cp ./conf/p4/bin/up4.json stratum:/etc/stratum/dummy.json
#docker cp ./conf/p4/bin/bmv2.json stratum:/etc/stratum/dummy.json
#docker cp ./conf/p4/bin/up4.txt stratum:/var/log/stratum/p4_reads.pb.txt.
#docker cp ./conf/p4/bin/up4.txt stratum:/var/log/stratum/p4_reads.pb.txt
#docker cp ./conf/p4/bin/up4.txt stratum:/var/log/stratum/p4_writes.pb.txt.

pid_stratum=$(sudo docker inspect -f '{{.State.Pid}}' stratum)
sudo ip link set ens803f2 netns $pid_stratum
sudo ip link set ens803f3 netns $pid_stratum


docker exec stratum sudo ip link set ens803f2 up
docker exec stratum sudo ip link set ens803f3 up

docker exec stratum sudo ip addr add 198.18.0.1/30 dev ens803f2 
docker exec stratum sudo ip addr add 198.19.0.1/30 dev ens803f3

docker exec stratum sudo apt install tcpdump -y
docker exec -it stratum bash

