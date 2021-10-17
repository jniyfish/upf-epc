# p4-upf-epc

sudo ./bazel-bin/stratum/hal/bin/bmv2/stratum_bmv2 --chassis_config_file=./stratum/hal/bin/bmv2/chassis_config.pb.txt --bmv2_log_level=debug

# tofino

set veth for tofino_model
```
sudo $SDE_INSTLL/bin/veth_setup.sh
```

run tofino model 
```
sde
./run_tofino_model.sh -p main
```

run stratum
```
cd ~/Desktop/stratum/stratum/hal/bin/barefoot/docker/
export CHASSIS_CONFIG=/path/to/chassis_config.pb.txt
./start-stratum-container.sh PLATFORM=barefoot-tofino-model -bf_switchd_backgroung=false -enable_onlp=false
```

compile p4 
```
buildp4 main.p4 //generate main.conf, context.conf
./compile.sh main //generate p4info.txt
```

compile json file
```
git clone https://github.com/p4lang/p4runtime-shell.git
cd ./p4runtime-CLI

./config_builders/tofino.py --ctx-json <path to context JSON> \
  --tofino-bin <path to tofino.bin> -p <program name> -o out.bin
# generate single p4info for tofino architecture
```

### Setup tna upf-epc
```
./run_tofino_model.sh
cd ~/Desktop/stratum/stratum/hal/bin/barefoot/docker/
export CHASSIS_CONFIG=/path/to/chassis_config.pb.txt
./start-stratum-container.sh PLATFORM=barefoot-tofino-model -bf_switchd_backgroung=false -enable_onlp=false
sudo ./docker_setup.sh

```

### Setup v1model upf-epc

run free5gc and UERANSIM

