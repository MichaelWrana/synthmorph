package synthmorph

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"golang.org/x/crypto/curve25519"
)

/*
CRYPTOGRAPHY STUFF
*/

// elliptic curve cryptography 🤯
func GenerateKeyPair() (privateKey, publicKey [32]byte, err error) {
	// Generate a random private key.
	if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return
	}
	// Derive the public key.
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// encrypt encrypts the plaintext using AES-GCM with the given key.
// The nonce is generated randomly and prepended to the ciphertext.
func encrypt(key, plaintext []byte) ([]byte, error) {
	// Create an AES cipher block from the key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Wrap the block cipher in GCM mode.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Create a random nonce of the required size.
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends the encrypted data to the nonce.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts the ciphertext using AES-GCM with the given key.
// It expects the nonce to be prepended to the ciphertext.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	// Create an AES cipher block from the key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Wrap the block cipher in GCM mode.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	// Extract the nonce and the actual ciphertext.
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// Decrypt the data.
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

/*
STRUCT FOR MANAGING BUFFER OF RECEIVED PACKETS
*/

type RTPStack struct {
	packets []*rtp.Packet
}

// Push adds an RTP packet to the top of the stack
func (s *RTPStack) Push(packet *rtp.Packet) {
	s.packets = append(s.packets, packet)
}

// Pop removes and returns the top RTP packet from the stack
func (s *RTPStack) Pop() *rtp.Packet {
	packet := s.packets[len(s.packets)-1]
	s.packets = s.packets[:len(s.packets)-1]
	return packet
}

// Size returns the number of packets in the stack
func (s *RTPStack) Size() int {
	return len(s.packets)
}

// IsEmpty returns whether the stack is empty
func (s *RTPStack) IsEmpty() bool {
	return len(s.packets) == 0
}

/*
STRUCT FOR MANAGING KEY EXCHANGE STATE INFORMATION
*/

type SynthmorphState struct {
	//cryptographic state information
	Lock         sync.Mutex
	PrivateKey   [32]uint8
	PublicKey    [32]uint8
	OtherPub     [32]uint8
	SharedSecret [32]byte

	//RTP connection state information
	SSRC uint32
	//Data received goes into this "buffer" : needs to change into a buffer
	RecvBuffer RTPStack
}

func NewSynthmorphState() SynthmorphState {
	state := SynthmorphState{}
	var err error
	state.PrivateKey, state.PublicKey, err = GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating receiver keys:", err)
	}
	state.SSRC = 0x12345678
	state.Lock = sync.Mutex{}
	return state
}

/*
LOCAL HELPER FUNCTIONS
*/

func printRTPPacket(packet *rtp.Packet) {
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

/*
MAIN SENDER/RECEIVER TOOLS
*/

func (s *SynthmorphState) SendData(videoTrack *webrtc.TrackLocalStaticRTP, header byte, payload []byte) {
	seq := uint16(1)
	timestamp := uint32(12345678)

	message := append([]byte{header}, payload...)

	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    96, // Dynamic payload type (e.g., for VP8)
			SequenceNumber: seq,
			Timestamp:      timestamp,
			SSRC:           0x11223344, // Example SSRC; typically randomized
		},
		// Set payload to "Hello World!"
		Payload: message,
	}

	if err := videoTrack.WriteRTP(pkt); err != nil {
		panic(err)
	}

	fmt.Printf("##### Sent Pkt, seqnum=%v##### \n", seq)
}

// interval is in seconds
func (s *SynthmorphState) SynthmorphPeriodicSender(videoTrack *webrtc.TrackLocalStaticRTP, interval int32) {
	time.Sleep(5 * time.Second)

	seq := uint16(2)
	timestamp := uint32(12345678)

	message := []byte("Hello World!")

	// Set ticker interval to 5 seconds
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {

		fmt.Printf("===== Encrypting Msg: %s =====\n", message)
		encryptedMsg, err := encrypt(s.SharedSecret[:], message)
		if err != nil {
			fmt.Println("Encryption error:", err)
			return
		}

		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    96, // Dynamic payload type (e.g., for VP8)
				SequenceNumber: seq,
				Timestamp:      timestamp,
				SSRC:           0x11223344, // Example SSRC; typically randomized
			},
			// Set payload to "Hello World!"
			Payload: encryptedMsg,
		}

		if err := videoTrack.WriteRTP(pkt); err != nil {
			panic(err)
		}

		fmt.Printf("##### Sent Pkt, seqnum=%v##### \n", seq)

		// Increment header fields for the next packet.
		seq++
		timestamp += 450000
	}
}

// Read packets
// this one should be called concurrently
func (s *SynthmorphState) SynthmorphPacketRecv(track *webrtc.TrackRemote) {
	for {
		packet, _, err := track.ReadRTP()
		if err != nil {
			log.Printf("Error reading RTP packet: %v\n", err)
			return
		}
		// figure out what to do with the incoming packet
		// see the protocol specification google doc for more info
		header := packet.Payload[0]
		switch header {
		case 0b00101111: //too specific, need to refine protocol a bit more, but gets the point across
			// (3) COMPUTE SHARED SECRET
			fmt.Printf("===== Recv PubKey =====: %d\n", packet.Payload[1:])
			s.OtherPub = *(*[32]uint8)(packet.Payload[1:]) // Unsafe but efficient conversion
			curve25519.ScalarMult(&s.SharedSecret, &s.PrivateKey, &s.OtherPub)
			fmt.Printf("===== Shared Scrt =====: %d\n", s.SharedSecret)
		default:

			fmt.Printf("##### Recv Pkt, seqnum=%v##### \n", packet.SequenceNumber)
			fmt.Printf("===== Decrypting Message: %s =====\n", packet.Payload)

			packet.Payload, err = decrypt(s.SharedSecret[:], packet.Payload)
			if err != nil {
				fmt.Println("Decryption error:", err)
				return
			}

			printRTPPacket(packet)
		}
	}
}

// Read packets
// this one should be called concurrently
func (s *SynthmorphState) SynthmorphRTCPLog(receiver *webrtc.RTPReceiver) {
	for {
		// Read the RTCP packets as they become available for our new remote track
		rtcpPackets, _, rtcpErr := receiver.ReadRTCP()
		if rtcpErr != nil {
			panic(rtcpErr)
		}

		for _, packet := range rtcpPackets {
			switch p := packet.(type) {
			case *rtcp.SenderReport:
				fmt.Printf("Received Sender Report: SSRC=%d, NTP=%d.%d, RTPTime=%d, PacketCount=%d, OctetCount=%d\n",
					p.SSRC, p.NTPTime>>32, p.NTPTime&0xFFFFFFFF, p.RTPTime, p.PacketCount, p.OctetCount)
			case *rtcp.ReceiverReport:
				fmt.Printf("Received Receiver Report: SSRC=%d, Reports=%d\n", p.SSRC, len(p.Reports))
				for i, report := range p.Reports {
					fmt.Printf("  Report %d: SSRC=%d, FractionLost=%d, TotalLost=%d, LastSeq=%d, Jitter=%d\n",
						i, report.SSRC, report.FractionLost, report.TotalLost, report.LastSequenceNumber, report.Jitter)
				}
			case *rtcp.SourceDescription:
				fmt.Printf("Received Source Description: %d descriptions\n", len(p.Chunks))
				for _, chunk := range p.Chunks {
					fmt.Printf("  Chunk: SSRC=%d, CNAME=%s\n", chunk.Source, chunk.Items[0].Text)
				}
			case *rtcp.PictureLossIndication:
				fmt.Printf("Received Picture Loss Indication for SSRC=%d\n", p.MediaSSRC)
			case *rtcp.FullIntraRequest:
				fmt.Printf("Received Full Intra Request for SSRC=%d\n", p.MediaSSRC)
			default:
				fmt.Printf("Received RTCP Packet: %v\n", p)
			}
		}
	}
}
