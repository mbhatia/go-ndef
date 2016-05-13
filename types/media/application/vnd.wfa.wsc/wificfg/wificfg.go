/***
    Copyright (c) 2016, Hector Sanjuan

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
***/

// BUG(hector): Multiple TLVs of the same type (for the ones we handle)
// will overwrite the value (except for Credentials). i.e. If several APChannel
// TLVs are included in the token, only the value from the last one is
// retained as the Payload's APChannel attribute.

// Package wificfg provides an implementation of NDEF Payloads for
// Wi-Fi Alliance's NFC Configuration Token Records. It is based on the
// Wi-Fi Simple Configuration Technical Specification v2.0.5 (section 10.1.2).
package wificfg

import (
	"bytes"
	"fmt"
	"strings"
)

// Authentication types
const (
	AuthOpen            = uint16(1) << 0
	AuthWPAPersonal     = uint16(1) << 1
	AuthShared          = uint16(1) << 2
	AuthWPAEnterprise   = uint16(1) << 3
	AuthWPA2Enterprise  = uint16(1) << 4
	AuthWPA2Personal    = uint16(1) << 5
	AuthWPAWPA2Personal = AuthWPAPersonal | AuthWPA2Personal
)

// Encryption types
const (
	EncNone    = uint16(1) << 0
	EncWEP     = uint16(1) << 2
	EncTKIP    = uint16(1) << 3
	EncAES     = uint16(1) << 4
	EncAESTKIP = EncTKIP | EncAES
)

// RF Bands
const (
	RF2_4Ghz = byte(1) << 0
	RF5_0Ghz = byte(1) << 1
	RF60Ghz  = byte(1) << 2
)

// TLV Types
const (
	tEnabled802_1X            = uint16(0x1062)
	tAPChannel                = uint16(0x1001)
	tAuthenticationType       = uint16(0x1003)
	tCredential               = uint16(0x100E)
	tEAPIdentity              = uint16(0x104D)
	tEAPType                  = uint16(0x1059)
	tEncryptionType           = uint16(0x100F)
	tKeyProvidedAutomatically = uint16(0x1061)
	tMACAddress               = uint16(0x1020)
	tNetworkIndex             = uint16(0x1026)
	tNetworkKey               = uint16(0x1027)
	tRFBands                  = uint16(0x103C)
	tSSID                     = uint16(0x1045)
	tVendorExtension          = uint16(0x1049)
)

// Payload stores a Wi-Fi Configuration Token NDEF Record Payload.
// This type implements the RecordPayload interface.
type Payload struct {
	Credentials []*Credential
	RFBand      byte
	APChannel   uint16
	MACAddress  [6]byte
	Version2    byte
	ExtraAttrs  []*TLV
}

// Credential represents a Wi-Fi Configuration Token credential.
// Each token can have multiple credentials. They define which
// network to connect to and need at least the SSID, the authentication type,
// the encryption type and the network key (password).
type Credential struct {
	// NetworkIndex int // Deprecated. Will use 1
	SSID                     string
	AuthenticationType       uint16
	EncryptionType           uint16
	NetworkKey               string
	MACAddress               [6]byte
	EAPType                  []byte
	EAPIdentity              string
	KeyProvidedAutomatically bool
	Enabled802_1X            bool
	NetworkKeyShareable      bool
	ExtraAttrs               []*TLV
}

// TLV is a generic placeholder for the different types of data that make up
// a Configuration Token (Payload) or a Credential. We only parse some TLVs,
// the rest are just stored in the ExtraAttr fields.
type TLV struct {
	T uint16
	L uint16
	V []byte
}

// New returns a pointer to a wificfg.Payload generated with the given
// parameters. This payload contains a single Credential.
//
// This set of arguments represents the minimum required set to produce a usable
// Configuration Token. For more complex uses, initialize the
// Payload and its Credentials objects manually.
func New(ssid string, key string, auth uint16, enc uint16) *Payload {
	cred := &Credential{
		SSID:               ssid,
		NetworkKey:         key,
		AuthenticationType: auth,
		EncryptionType:     enc,
	}
	return &Payload{
		Credentials: []*Credential{cred},
		Version2:    0x20,
	}
}

// String returns a human readable output for this payload, including
// each of the credentials in it.
func (wificfg *Payload) String() string {
	str := "configuration-token\n\n"

	str += "Wi-Fi Confituration Token:\n\n"
	str += fmt.Sprintf("RF Band: %s (%d)\n", _RFBandString(wificfg.RFBand),
		wificfg.RFBand)
	str += fmt.Sprintf("AP Channel: %d\n", wificfg.APChannel)
	str += fmt.Sprintf("MAC Address (BSSID): % 02x\n", wificfg.MACAddress)
	str += fmt.Sprintf("Version2: %d.%d\n", wificfg.Version2>>4,
		wificfg.Version2&0x0F)
	str += "Credentials:\n"
	for i, cr := range wificfg.Credentials {
		str += fmt.Sprintf("  %d:\n", i)
		credStr := cr.String()
		for _, l := range strings.Split(credStr, "\n") {
			str += "    " + l + "\n"
		}
	}
	if l := len(wificfg.ExtraAttrs); l > 0 {
		str += fmt.Sprintf("\nThe token contains %d other attributes\n", l)
	}

	return str
}

// String returns a human readable output of a Credential.
func (cred *Credential) String() string {
	str := ""
	str += fmt.Sprintf("SSID: %s\n", cred.SSID)
	str += fmt.Sprintf("Authentication Type: %s (%d)\n",
		_AuthTypeString(cred.AuthenticationType),
		cred.AuthenticationType)
	str += fmt.Sprintf("Encryption Type: %s (%d)\n",
		_EncTypeString(cred.EncryptionType),
		cred.EncryptionType)
	// FIXME: HEX keys....
	str += fmt.Sprintf("Network Key: %s\n", cred.NetworkKey)
	str += fmt.Sprintf("MAC Address: % 02x\n", cred.MACAddress)
	str += fmt.Sprintf("EAP Type: % 02x. EAP Identity: %s\n",
		cred.EAPType, cred.EAPIdentity)
	str += fmt.Sprintf("Key provided automatically: %t\n",
		cred.KeyProvidedAutomatically)
	str += fmt.Sprintf("802.1X Enabled: %t\n",
		cred.Enabled802_1X)
	str += fmt.Sprintf("Network Key Shareable: %t\n",
		cred.NetworkKeyShareable)
	if l := len(cred.ExtraAttrs); l > 0 {
		str += fmt.Sprintf("\nThe credential contains %d other attributes\n", l)
	}
	return str
}

// Type returns the mime type of this payload.
func (wificfg *Payload) Type() string {
	return "application/vnd.wfa.wsc"
}

func (tlv *TLV) marshal() []byte {
	var buffer bytes.Buffer
	t := uint16ToBytes(tlv.T)
	buffer.Write(t[:])
	l := uint16ToBytes(tlv.L)
	buffer.Write(l[:])
	buffer.Write(tlv.V)
	return buffer.Bytes()
}

// Leave tlv as-is
func (tlv *TLV) unmarshal(buf []byte) (rLen int, err error) {
	bytesBuf := bytes.NewBuffer(buf)
	t1, err := bytesBuf.ReadByte()
	if err != nil {
		return 1, err
	}
	t2, err := bytesBuf.ReadByte()
	if err != nil {
		return 2, err
	}
	l1, err := bytesBuf.ReadByte()
	if err != nil {
		return 3, err
	}
	l2, err := bytesBuf.ReadByte()
	if err != nil {
		return 4, err
	}
	t := bytesToUint16([2]byte{t1, t2})
	l := bytesToUint16([2]byte{l1, l2})
	v := make([]byte, l, l)
	n, _ := bytesBuf.Read(v)
	tlv.T = t
	tlv.L = l
	tlv.V = v
	return n + 4, nil
}

// String provides a human-readable output for a TLV.
func (tlv *TLV) String() string {
	return fmt.Sprintf("T: %04x. L: %d. V: % 02x", tlv.T, tlv.L, tlv.V)
}

func (cred *Credential) marshal() []byte {
	var buf bytes.Buffer
	// NetworkIndex
	tlv := &TLV{tNetworkIndex, 1, []byte{1}}
	buf.Write(tlv.marshal())
	// SSID
	tlv = &TLV{tSSID, uint16(len([]byte(cred.SSID))), []byte(cred.SSID)}
	buf.Write(tlv.marshal())
	// Auth Type
	authBytes := uint16ToBytes(cred.AuthenticationType)
	tlv = &TLV{tAuthenticationType, 2, authBytes[:]}
	buf.Write(tlv.marshal())
	// Enc type
	encBytes := uint16ToBytes(cred.EncryptionType)
	tlv = &TLV{tEncryptionType, 2, encBytes[:]}
	buf.Write(tlv.marshal())
	// Network key
	tlv = &TLV{tNetworkKey, uint16(len([]byte(cred.NetworkKey))), []byte(cred.NetworkKey)}
	buf.Write(tlv.marshal())
	if !bytes.Equal(cred.MACAddress[:], []byte{0, 0, 0, 0, 0, 0}) {
		tlv = &TLV{tMACAddress, 6, cred.MACAddress[:]}
		buf.Write(tlv.marshal())
	}
	// EAP Type when not empty
	if l := len(cred.EAPType); l > 0 {
		tlv = &TLV{tEAPType, uint16(l), cred.EAPType}
		buf.Write(tlv.marshal())
	}
	// EAP identity when not empty
	if l := len([]byte(cred.EAPIdentity)); l > 0 {
		tlv = &TLV{tEAPIdentity, uint16(l), []byte(cred.EAPIdentity)}
		buf.Write(tlv.marshal())
	}
	// Key provided automatically when set
	if cred.KeyProvidedAutomatically {
		tlv = &TLV{tKeyProvidedAutomatically, 1, []byte{1}}
		buf.Write(tlv.marshal())
	}
	// 802.1X
	if cred.Enabled802_1X {
		tlv = &TLV{tEnabled802_1X, 1, []byte{1}}
		buf.Write(tlv.marshal())
	}
	// Network Key Shareable - goes inside WFA Vendor extension
	if cred.NetworkKeyShareable {
		tlv = &TLV{tVendorExtension, 6, []byte{
			0x00, // Vendor ID 3 bytes
			0x37,
			0x2A,
			0x02, // Network Key shareable
			0x01, // Length
			0x01, // True
		}}
		buf.Write(tlv.marshal())
	}

	for _, attr := range cred.ExtraAttrs {
		buf.Write(attr.marshal())
	}

	return buf.Bytes()
}

func (cred *Credential) unmarshal(buf []byte) {
	*cred = Credential{}
	i := 0
	for i < len(buf) {
		tlv := new(TLV)
		tlvLen, err := tlv.unmarshal(buf[i:])
		i += tlvLen
		if err != nil { // we don't parse this shit anymore
			break
		}
		switch tlv.T {
		case tNetworkIndex:
			continue
		case tEnabled802_1X:
			cred.Enabled802_1X = tlv.V[0] == 1
		case tSSID:
			cred.SSID = string(tlv.V)
		case tAuthenticationType:
			if len(tlv.V) == 2 {
				cred.AuthenticationType = bytesToUint16([2]byte{
					tlv.V[0],
					tlv.V[1]})
			}
		case tEncryptionType:
			if len(tlv.V) == 2 {
				cred.EncryptionType = bytesToUint16([2]byte{
					tlv.V[0],
					tlv.V[1]})
			}
		case tNetworkKey:
			cred.NetworkKey = string(tlv.V)
		case tMACAddress:
			if len(tlv.V) == 6 {
				copy(cred.MACAddress[:], tlv.V)
			}
		case tEAPType:
			cred.EAPType = tlv.V
		case tEAPIdentity:
			cred.EAPIdentity = string(tlv.V)
		case tKeyProvidedAutomatically:
			cred.KeyProvidedAutomatically = tlv.V[0] == 1
		case tVendorExtension:
			if len(tlv.V) == 6 && tlv.V[0] == 0x00 &&
				tlv.V[1] == 0x37 && tlv.V[2] == 0x2A &&
				tlv.V[3] == 0x02 && tlv.V[4] == 0x01 &&
				tlv.V[5] == 1 {
				cred.NetworkKeyShareable = true
				continue
			}
			fallthrough
		default:
			cred.ExtraAttrs = append(cred.ExtraAttrs, tlv)
		}
	}
}

// Marshal returns the bytes representing the payload
func (wificfg *Payload) Marshal() []byte {
	var buf bytes.Buffer
	// Credentials
	if len(wificfg.Credentials) > 0 {
		for _, cr := range wificfg.Credentials {
			crBytes := cr.marshal()
			tlv := &TLV{tCredential, uint16(len(crBytes)), crBytes}
			buf.Write(tlv.marshal())
		}
	}
	// RFBand
	if wificfg.RFBand != 0 {
		tlv := &TLV{tRFBands, 1, []byte{wificfg.RFBand}}
		buf.Write(tlv.marshal())
	}
	// AP channel
	if wificfg.APChannel != 0 {
		ch := uint16ToBytes(wificfg.APChannel)
		tlv := &TLV{tAPChannel, 2, ch[:]}
		buf.Write(tlv.marshal())
	}

	if !bytes.Equal(wificfg.MACAddress[:], []byte{0, 0, 0, 0, 0, 0}) {
		tlv := &TLV{tMACAddress, 6, wificfg.MACAddress[:]}
		buf.Write(tlv.marshal())
	}
	// Version2
	tlv := &TLV{tVendorExtension, 6, []byte{
		0x00, // Vendor ID 3 bytes
		0x37,
		0x2A,
		0x00, // Network Key shareable
		0x01, // Length
		wificfg.Version2,
	}}
	buf.Write(tlv.marshal())

	for _, at := range wificfg.ExtraAttrs {
		buf.Write(at.marshal())
	}

	return buf.Bytes()
}

// Unmarshal parses a generic payload into a Configuration Token
func (wificfg *Payload) Unmarshal(buf []byte) {
	*wificfg = Payload{} // Reset
	i := 0
	for i < len(buf) {
		tlv := new(TLV)
		tlvLen, err := tlv.unmarshal(buf[i:])
		i += tlvLen
		if err != nil { // stop parsing
			break
		}
		switch tlv.T {
		case tCredential:
			cred := new(Credential)
			cred.unmarshal(tlv.V)
			wificfg.Credentials = append(wificfg.Credentials, cred)
		case tRFBands:
			if len(tlv.V) == 1 {
				wificfg.RFBand = tlv.V[0]
			}
		case tAPChannel:
			if len(tlv.V) == 2 {
				wificfg.APChannel = bytesToUint16([2]byte{
					tlv.V[0],
					tlv.V[1]})
			}
		case tMACAddress:
			if len(tlv.V) == 6 {
				copy(wificfg.MACAddress[:], tlv.V)
			}
		case tVendorExtension:
			if len(tlv.V) == 6 && tlv.V[0] == 0x00 &&
				tlv.V[1] == 0x37 && tlv.V[2] == 0x2A &&
				tlv.V[3] == 0x00 && tlv.V[4] == 0x01 {
				wificfg.Version2 = tlv.V[5]
				continue
			}
			fallthrough
		default:
			wificfg.ExtraAttrs = append(wificfg.ExtraAttrs, tlv)
		}
	}
}

// Len is the length of the byte slice resulting of Marshaling
// this Payload.
func (wificfg *Payload) Len() int {
	return len(wificfg.Marshal())
}

func _RFBandString(rfb byte) string {
	switch rfb {
	case 0:
		return "Unset"
	case RF2_4Ghz:
		return "2.4Ghz"
	case RF5_0Ghz:
		return "5.0Ghz"
	case RF60Ghz:
		return "60Ghz"
	default:
		return "Invalid"
	}
}

func _EncTypeString(enc uint16) string {
	switch enc {
	case EncNone:
		return "None"
	case EncWEP:
		return "WEP"
	case EncTKIP:
		return "TKIP"
	case EncAES:
		return "AES"
	case EncAESTKIP:
		return "AES/TKIP"
	default:
		return "Invalid"
	}
}

func _AuthTypeString(auth uint16) string {
	switch auth {
	case AuthOpen:
		return "Open"
	case AuthWPAPersonal:
		return "WPA-Personal"
	case AuthShared:
		return "Shared"
	case AuthWPAEnterprise:
		return "WPA-Enterprise"
	case AuthWPA2Enterprise:
		return "WPA2-Enterprise"
	case AuthWPA2Personal:
		return "WPA2-Personal"
	case AuthWPAWPA2Personal:
		return "WPA/WPA2-Personal"
	default:
		return "Invalid"
	}
}

// BytesToUint16 takes a 2-byte array and returns the corresponding
// uint16 value (BigEndian).
func bytesToUint16(field [2]byte) uint16 {
	return uint16(field[0])<<8 | uint16(field[1])
}

// Uint16ToBytes takes an uint16 value and returns the corresponding
// 2-byte array (BigEndian).
func uint16ToBytes(value uint16) [2]byte {
	byte0 := byte(value >> 8)
	byte1 := byte(0x00ff & value) //Probably the casting would suffice
	return [2]byte{byte0, byte1}
}
