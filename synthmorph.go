package synthmorph

import (
	"fmt"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

func PrintRTPPacket(packet *rtp.Packet) {
	// Print header details.
	fmt.Printf("RTP Header:\n")
	fmt.Printf("  Version: %d\n", packet.Version)
	fmt.Printf("  Padding: %v\n", packet.Padding)
	fmt.Printf("  Extension: %v\n", packet.Extension)
	fmt.Printf("  Marker: %v\n", packet.Marker)
	fmt.Printf("  PayloadType: %d\n", packet.PayloadType)
	fmt.Printf("  SequenceNumber: %d\n", packet.SequenceNumber)
	fmt.Printf("  Timestamp: %d\n", packet.Timestamp)
	fmt.Printf("  SSRC: %d\n", packet.SSRC)

	payloadStr := string(packet.Payload)
	fmt.Printf("Payload (string): %s\n", payloadStr)
	fmt.Printf("Payload (hex): %x\n", packet.Payload)
}

// interval is in seconds
func SynthmorphSender(videoTrack *webrtc.TrackLocalStaticRTP, interval int32) {
	seq := uint16(1)
	timestamp := uint32(12345678)
	// Set ticker interval to 5 seconds
	ticker := time.NewTicker(time.Duration(interval*1000) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    96, // Dynamic payload type (e.g., for VP8)
				SequenceNumber: seq,
				Timestamp:      timestamp,
				SSRC:           0x11223344, // Example SSRC; typically randomized
			},
			// Set payload to "Hello World!"
			Payload: []byte("Hello World!"),
		}

		if err := videoTrack.WriteRTP(pkt); err != nil {
			panic(err)
		}

		fmt.Printf("##### Sent Pkt, seqnum=%v##### \n", seq)

		// Increment header fields for the next packet.
		seq++
		timestamp += 6000000
	}
}

// Some sort of wrapper - part of the Pion API
func SynthmorphReceiverTrack(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	fmt.Println("Reciever Called")
}

// Actually read packets - must be run concurrently
func SynthmorphPacketRecv(track *webrtc.TrackRemote) {

}
