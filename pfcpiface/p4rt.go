// SPDX-License-Identifier: Apache-2.0
// Copyright 2021-present Open Networking Foundation

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
)

var (
	setSWinfo = 0
	p4RtcServerIP   = flag.String("p4RtcServerIP", "", "P4 Server ip")
	p4RtcServerPort = flag.String("p4RtcServerPort", "", "P4 Server port")
)

// P4rtcInfo : P4 runtime interface settings.
type P4rtcInfo struct {
	AccessIP    string `json:"access_ip"`
	P4rtcServer string `json:"p4rtc_server"`
	P4rtcPort   string `json:"p4rtc_port"`
	UEIP        string `json:"ue_ip_pool"`
}

// TODO: convert uint8 to enum.
const (
	preQosPdrCounter  uint8 = 0 // Pre qos pdr ctr
	postQosPdrCounter uint8 = 1 // Post qos pdr ctr
)

type counter struct {
	maxSize   uint64
	counterID uint64
	allocated map[uint64]uint64
	// free      map[uint64]uint64
}

type p4rtc struct {
	host             string
	deviceID         uint64
	timeout          uint32
	accessIPMask     net.IPMask
	accessIP         net.IP
	p4rtcServer      string
	p4rtcPort        string
	p4client         *P4rtClient
	counters         []counter
	pfcpConn         *PFCPConn
	reportNotifyChan chan<- uint64
	endMarkerChan    chan []byte
}

func (p *p4rtc) summaryLatencyJitter(uc *upfCollector, ch chan<- prometheus.Metric) {
}

func (p *p4rtc) portStats(uc *upfCollector, ch chan<- prometheus.Metric) {
}

func setSwitchInfo(p4rtClient *P4rtClient) (net.IP, net.IPMask, error) {
	log.Println("Set Switch Info")
	log.Println("device id ", (*p4rtClient).DeviceID)

	//v1model
	//p4InfoPath := "/bin/p4info.txt"
	//deviceConfigPath := "/bin/bmv2.json"

	//tna
	p4InfoPath := "/bin/up4.txt"
	deviceConfigPath := "/bin/out.bin"

	errin := p4rtClient.GetForwardingPipelineConfig()
	if errin != nil {
		errin = p4rtClient.SetForwardingPipelineConfig(p4InfoPath, deviceConfigPath)
		if errin != nil {
			log.Println("set forwarding pipeling config failed. ", errin)
			return nil, nil, errin
		}
	}
//insert interface info start
	

	if setSWinfo == 0{
		setSWinfo = 1
		log.Println("setSWinfo: ", setSWinfo)
		S1UipByte := net.IP{ 198, 18, 0, 1}
		S1UinsertIntfEntry := IntfTableEntry{
			IP: S1UipByte,
			PrefixLen: 32,
			SrcIntf:   "ACCESS",
			Direction: "UPLINK",
		}
		S1UerrInte := p4rtClient.WriteInterfaceTable(S1UinsertIntfEntry, 1)
		if S1UerrInte != nil {
			log.Println("Write S1UInterface table failed ", S1UerrInte)
		}
		SGIipByte := net.IP{ 60, 60, 0, 1}
		SGIinsertIntfEntry := IntfTableEntry{
			IP: SGIipByte,
			PrefixLen: 32,
			SrcIntf:   "CORE",
			Direction: "DOWNLINK",
		}
		SGIerrInte := p4rtClient.WriteInterfaceTable(SGIinsertIntfEntry, 1)
		if SGIerrInte != nil {
			log.Println("Write SGIInterface table failed ", SGIerrInte)
		} 
		N3stationEntry := StationTableEntry{
			DST_MAC: []byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5c},
		}
		N3StationerrInte := p4rtClient.WriteStationTable(N3stationEntry, 1)
		if N3StationerrInte != nil {
			log.Println("Write N3StationInterface table failed ", N3StationerrInte)
		}
		N6stationEntry := StationTableEntry{
			DST_MAC: []byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5d},
		}
		N6StationerrInte := p4rtClient.WriteStationTable(N6stationEntry, 1)
		if N6StationerrInte != nil {
			log.Println("Write N6StationInterface table failed ", N6StationerrInte)
		}

		
		UlAclEntry := ACLTableEntry{
			inport       : []byte{0x00, 0x01},
			src_iface    : []byte{0x01},
			eth_src      : []byte{0x88, 0x00, 0x66, 0x99, 0x5b, 0x47},
			eth_dst      : []byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5c},
			eth_type     : []byte{0x08, 0x00},
			ipv4_src     : net.IP{60, 60, 0, 1} ,
			ipv4_dst     : net.IP{198, 19, 0, 2} ,
			ipv4_proto   : []byte{0x01},
			l4_sport     : []byte{0x08, 0x68},
			l4_dport     : []byte{0x08, 0x68},
			egress_port  : []byte{0x00, 0x02},
		}
		DlAclEntry := ACLTableEntry{
			inport       : []byte{0x00, 0x02},
			src_iface    : []byte{0x02},
			eth_src      : []byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5c},//[]byte{0x7c, 0xd3, 0x0a, 0x90, 0x83, 0xc1},
			eth_dst      : []byte{0x88, 0x00, 0x66, 0x99, 0x5b, 0x47},//[]byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5d},
			eth_type     : []byte{0x08, 0x00},
			ipv4_src     : net.IP{ 198, 19, 0, 2} ,
			ipv4_dst     : net.IP{60, 60, 0, 1} ,
			ipv4_proto   : []byte{0x01},
			l4_sport     : []byte{0x00, 0x00},
			l4_dport     : []byte{0x00, 0x00},
			egress_port  : []byte{0x00, 0x01},
		}
		log.Println("Insert ACL")
		UlAclErr := p4rtClient.WriteAclTable(UlAclEntry ,1)
		if UlAclErr != nil {
			log.Println("Write ACL table failed ", UlAclErr)
		}
		DlAclErr := p4rtClient.WriteAclTable(DlAclEntry ,1)
		if DlAclErr != nil {
			log.Println("Write ACL table failed ", DlAclErr)
		}
		ULrouteEntry := RouteTableEntry{
			IP	:	net.IP{ 198, 19, 0, 2},
			PrefixLen	:	32,
			SRC_MAC		: []byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5d},
			DST_MAC		: []byte{0x7c, 0xd3, 0x0a, 0x90, 0x83, 0xc1},
			Port        : []byte{0x00, 0x02},
		}
		DLrouteEntry := RouteTableEntry{
			IP	:	net.IP{ 198, 18, 0, 2},
			PrefixLen	:	32,
			SRC_MAC		: []byte{0x00, 0x15, 0x4d, 0x13, 0x63, 0x5c},
			DST_MAC		: []byte{0x88, 0x00, 0x66, 0x99, 0x5b, 0x47},
			Port        : []byte{0x00, 0x01},
		}
		p4rtClient.WriteRoutingTable(ULrouteEntry ,1)
		p4rtClient.WriteRoutingTable(DLrouteEntry ,1)
		
		setSWinfo = 2
		log.Println("setSWinfo: ", setSWinfo)
		//return nil, nil, errin
	}
	
//insert interface info end
	intfEntry := IntfTableEntry{
		SrcIntf:   "ACCESS",
		Direction: "UPLINK",
	}
	errin = p4rtClient.ReadInterfaceTable(&intfEntry)
	if errin != nil {
		log.Println("Read Interface table failed ", errin)
		//return nil, nil, errin
	}

	log.Println("accessip after read intf ", intfEntry.IP)
	accessIP := net.IP(intfEntry.IP)
	accessIPMask := net.CIDRMask(intfEntry.PrefixLen, 32)
	log.Println("AccessIP: ", accessIP, ", AccessIPMask: ", accessIPMask)

	return accessIP, accessIPMask, errin
}

func (c *counter) init() {
	c.allocated = make(map[uint64]uint64)
}

func setCounterSize(p *p4rtc, counterID uint8, name string) error {
	if p.p4client != nil {
		for _, ctr := range p.p4client.P4Info.Counters {
			if ctr.Preamble.Name == name {
				log.Println("maxsize : ", ctr.Size)
				log.Println("ctr ID : ", ctr.Preamble.Id)
				p.counters[counterID].maxSize = uint64(ctr.Size)
				p.counters[counterID].counterID = uint64(ctr.Preamble.Id)

				return nil
			}
		}
	}

	errin := fmt.Errorf("countername not found %s", name)

	return errin
}

func (p *p4rtc) setInfo(conn *net.UDPConn, addr net.Addr, pconn *PFCPConn) {
	log.Println("setUDP Conn ", conn)

	p.pfcpConn = pconn
}

func resetCounterVal(p *p4rtc, counterID uint8, val uint64) {
	log.Println("delete counter val ", val)
	delete(p.counters[counterID].allocated, val)
}

func getCounterVal(p *p4rtc, counterID uint8, pdrID uint32) (uint64, error) {
	/*
	   loop :
	      random counter generate
	      check allocated map
	      if not in map then return counter val.
	      if present continue
	      if loop reaches max break and fail.
	*/
	var val uint64

	ctr := &p.counters[counterID]
	for i := 0; i < int(ctr.maxSize); i++ {
		rand.Seed(time.Now().UnixNano())

		val = uint64(rand.Intn(int(ctr.maxSize)-1) + 1)
		if _, ok := ctr.allocated[val]; !ok {
			log.Println("key not in allocated map ", val)

			ctr.allocated[val] = 1

			return val, nil
		}
	}

	return 0, fmt.Errorf("key alloc fail %v", val)
}

func (p *p4rtc) exit() {
	log.Println("Exit function P4rtc")
}

func (p *p4rtc) channelSetup() (*P4rtClient, error) {
	log.Println("Channel Setup.")

	localclient, errin := CreateChannel(p.host, p.deviceID, p.timeout, p.reportNotifyChan)
	if errin != nil {
		log.Println("create channel failed : ", errin)
		return nil, errin
	}

	if localclient != nil {
		log.Println("device id ", (*localclient).DeviceID)

		p.accessIP, p.accessIPMask, errin = setSwitchInfo(localclient)
		if errin != nil {
			log.Println("Switch set info failed ", errin)
			return nil, errin
		}

		log.Println("accessIP, Mask ", p.accessIP, p.accessIPMask)
	} else {
		log.Println("p4runtime client is null.")
		return nil, errin
	}

	return localclient, nil
}

func initCounter(p *p4rtc) error {
	log.Println("Initialize counters for p4client.")

	var errin error

	if p.p4client == nil {
		errin = fmt.Errorf("can't initialize counter. P4client null")
		return errin
	}

	p.counters = make([]counter, 2)
	
	errin = setCounterSize(p, preQosPdrCounter, "PreQosPipe.pre_qos_pdr_counter")
	if errin != nil {
		log.Println("preQosPdrCounter counter not found : ", errin)
	}

	errin = setCounterSize(p, postQosPdrCounter, "PostQosPipe.post_qos_pdr_counter")
	if errin != nil {
		log.Println("postQosPdrCounter counter not found : ", errin)
	}

	for i := range p.counters {
		log.Println("init maps for counters.")
		p.counters[i].init()
	}

	return nil
}

func (p *p4rtc) isConnected(accessIP *net.IP) bool {
	var errin error
	if p.p4client == nil {
		p.p4client, errin = p.channelSetup()
		if errin != nil {
			log.Println("create channel failed : ", errin)
			return false
		}

		if accessIP != nil {
			*accessIP = p.accessIP
		}

		errin = p.p4client.ClearPdrTable()
		if errin != nil {
			log.Println("clear PDR table failed : ", errin)
		}

		errin = p.p4client.ClearFarTable()
		if errin != nil {
			log.Println("clear FAR table failed : ", errin)
		}

		//errin = initCounter(p)
		//if errin != nil {
		//	log.Println("Counter Init failed. : ", errin)
		//	return false
		//}
	}

	return true
}

func (p *p4rtc) sendDeleteAllSessionsMsgtoUPF() {
	log.Println("Loop through sessions and delete all entries p4")

	//if (p.pfcpConn != nil) && (p.pfcpConn.mgr != nil) {
	//	for seidKey, value := range p.pfcpConn.mgr.sessions {
	//		p.sendMsgToUPF(upfMsgTypeDel, value.pdrs, value.fars, nil)
	//		p.pfcpConn.mgr.RemoveSession(seidKey)
	//	}
	//}
}

func (p *p4rtc) sim(u *upf, method string) {
	log.Println("simulator mode in p4rt not supported")
}

func (p *p4rtc) setUpfInfo(u *upf, conf *Conf) {
	log.Println("setUpfInfo p4rtc")

	var errin error

	u.accessIP, p.accessIPMask = ParseStrIP(conf.P4rtcIface.AccessIP)
	log.Println("AccessIP: ", u.accessIP, ", AccessIPMask: ", p.accessIPMask)

	p.p4rtcServer = conf.P4rtcIface.P4rtcServer
	log.Println("p4rtc server ip/name", p.p4rtcServer)
	p.p4rtcPort = conf.P4rtcIface.P4rtcPort
	p.reportNotifyChan = u.reportNotifyChan

	if *p4RtcServerIP != "" {
		p.p4rtcServer = *p4RtcServerIP
	}

	if *p4RtcServerPort != "" {
		p.p4rtcPort = *p4RtcServerPort
	}

	u.coreIP = net.ParseIP(net.IPv4zero.String())

	log.Println("onos server ip ", p.p4rtcServer)
	log.Println("onos server port ", p.p4rtcPort)
	log.Println("n4 ip ", u.n4SrcIP.String())

	p.host = p.p4rtcServer + ":" + p.p4rtcPort
	log.Println("server name: ", p.host)
	p.deviceID = 1
	p.timeout = 30
	p.p4client, errin = p.channelSetup()
	u.accessIP = p.accessIP

	if errin != nil {
		log.Println("create channel failed : ", errin)
	} else {
		errin = p.p4client.ClearPdrTable()
		if errin != nil {
			log.Println("clear PDR table failed : ", errin)
		}

		errin = p.p4client.ClearFarTable()
		if errin != nil {
			log.Println("clear FAR table failed : ", errin)
		}
		
	}

	errin = initCounter(p)
	if errin != nil {
		log.Println("Counter Init failed. : ", errin)
	}

	if conf.EnableEndMarker {
		log.Println("Starting end marker loop")

		p.endMarkerChan = make(chan []byte, 1024)
		go p.endMarkerSendLoop(p.endMarkerChan)
	}
}

func (p *p4rtc) sendEndMarkers(endMarkerList *[][]byte) error {
	for _, eMarker := range *endMarkerList {
		p.endMarkerChan <- eMarker
	}

	return nil
}

func (p *p4rtc) endMarkerSendLoop(endMarkerChan chan []byte) {
	for outPacket := range endMarkerChan {
		err := p.p4client.SendPacketOut(outPacket)
		if err != nil {
			log.Println("end marker write failed")
		}
	}
}

func (p *p4rtc) sendMsgToUPF(method upfMsgType, pdrs []pdr, fars []far, qers []qer) uint8 {
	log.Println("sendMsgToUPF p4")

	var (
		funcType uint8
		//err      error
		//val      uint64
		cause    uint8 = ie.CauseRequestRejected
	)

	if !p.isConnected(nil) {
		log.Println("p4rtc server not connected")
		return cause
	}
	
	switch method {
	case upfMsgTypeAdd:
		{
			funcType = FunctionTypeInsert
			//for i := range pdrs {
			//	val, err = getCounterVal(p,
			//		preQosPdrCounter, pdrs[i].pdrID)
			//	if err != nil {
			//		log.Println("Counter id alloc failed ", err)
			//		return cause
			//	}
			//	pdrs[i].ctrID = uint32(val)
			//}
		}
	case upfMsgTypeDel:
		{
			funcType = FunctionTypeDelete
			for i := range pdrs {
				resetCounterVal(p, preQosPdrCounter,
					uint64(pdrs[i].ctrID))
			}
		}
	case upfMsgTypeMod:
		{
			funcType = FunctionTypeUpdate
		}
	default:
		{
			log.Println("Unknown method : ", method)
			return cause
		}
	}

	for _, pdr := range pdrs {
		log.Traceln(pdr)
		log.Traceln("write pdr funcType : ", funcType)
		log.Println("index: ", funcType)
		errin := p.p4client.WritePdrTable(pdr, funcType)
		if errin != nil {
			resetCounterVal(p, preQosPdrCounter, uint64(pdr.ctrID))
			log.Println("pdr entry function failed ", errin)

			return cause
		}
	}

	for _, far := range fars {
		log.Traceln(far)
		log.Traceln("write far funcType : ", funcType)
		errin := p.p4client.WriteFarTable(far, funcType)
		if errin != nil {
			log.Println("far entry function failed ", errin)
			return cause
		}
	}
	//p.p4client.WritePdrTable(pdr, funcType)
	cause = ie.CauseRequestAccepted

	return cause
}
