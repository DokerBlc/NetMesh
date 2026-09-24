//go:build packet

// Modo paquete (fidelidad de red): responde ARP, TCP SYN e ICMP por las
// IPs señuelo para que un escaneo (nmap) las vea como dispositivos
// reales. Requiere privilegios (root) y compilar con `-tags packet`.
package main

import (
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// startPacketMode inicia el respondedor de paquetes sobre una interfaz.
// Es bloqueante: se debe invocar en una goroutine.
func startPacketMode(iface string, ips []string) {
	if iface == "" {
		log.Printf("[packet] modo paquete sin -iface; omitido")
		return
	}
	if len(ips) == 0 {
		log.Printf("[packet] sin IPs señuelo; omitido")
		return
	}

	decoy := make(map[string]bool, len(ips))
	for _, ip := range ips {
		decoy[ip] = true
	}

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		log.Printf("[packet] interfaz %s no encontrada: %v", iface, err)
		return
	}
	srcMAC := ifaceObj.HardwareAddr

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("[packet] no se pudo abrir %s (¿root?): %v", iface, err)
		return
	}
	defer handle.Close()

	log.Printf("[packet] respondiendo por %d IPs señuelo en %s", len(decoy), iface)

	var mu sync.Mutex
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		mu.Lock()
		handlePacket(handle, packet, srcMAC, decoy)
		mu.Unlock()
	}
}

func handlePacket(handle *pcap.Handle, packet gopacket.Packet, srcMAC net.HardwareAddr, decoy map[string]bool) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	// ARP: responder "who-has" de nuestras IPs.
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		if arp.Operation == layers.ARPRequest && decoy[net.IP(arp.DstProtAddress).String()] {
			reply := &layers.ARP{
				AddrType:          arp.AddrType,
				Protocol:          arp.Protocol,
				HwAddressSize:     arp.HwAddressSize,
				ProtAddressSize:   arp.ProtAddressSize,
				Operation:         layers.ARPReply,
				SourceHwAddress:   srcMAC,
				SourceProtAddress: arp.DstProtAddress,
				DstHwAddress:      arp.SourceHwAddress,
				DstProtAddress:    arp.SourceProtAddress,
			}
			ethResp := &layers.Ethernet{
				SrcMAC: srcMAC, DstMAC: eth.SrcMAC,
				EthernetType: layers.EthernetTypeARP,
			}
			_ = send(handle, ethResp, reply)
		}
		return
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)
	if !decoy[ip.DstIP.String()] {
		return
	}

	// ICMP echo → echo reply.
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			reply := &layers.ICMPv4{
				TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
				Id:       icmp.Id, Seq: icmp.Seq,
			}
			sendIPv4(handle, eth, ip, reply, layers.IPProtocolICMPv4)
		}
		return
	}

	// TCP SYN → SYN-ACK (hace ver los puertos como abiertos).
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			reply := &layers.TCP{
				SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
				Seq: 0, Ack: tcp.Seq + 1,
				SYN: true, ACK: true, Window: 64240,
			}
			sendIPv4(handle, eth, ip, reply, layers.IPProtocolTCP)
		}
	}
}

func sendIPv4(handle *pcap.Handle, eth *layers.Ethernet, ip *layers.IPv4,
	payload gopacket.SerializableLayer, proto layers.IPProtocol) {
	ipResp := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip.DstIP, DstIP: ip.SrcIP, Protocol: proto,
	}
	ethResp := &layers.Ethernet{
		SrcMAC: eth.DstMAC, DstMAC: eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	_ = send(handle, ethResp, ipResp, payload)
}

func send(handle *pcap.Handle, ls ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}
