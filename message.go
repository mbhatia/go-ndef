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

package ndef

import (
	"bytes"
	"fmt"
	"strings"
)

// Message represents an NDEF Message, which is a collection of one or
// more NDEF Records.
//
// Most common types of NDEF Messages (URI, Media) only have a single
// record. However, others, like Smart Posters, have multiple ones.
type Message struct {
	Records []*Record
}

// NewMessage returns a pointer to a Message initialized with a single Record
// with the TNF, Type, ID and Payload values.
//
// New does not check if the provided information is aligned with the specs.
func NewMessage(tnf byte, rtype string, id string, payload []byte) *Message {
	r := &Record{
		TNF:     tnf,
		Type:    rtype,
		ID:      id,
		Payload: makeRecordPayload(tnf, rtype, payload),
	}
	return &Message{
		[]*Record{r},
	}
}

// NewTextMessage returns a pointer to a Message with a single Record
// of WellKnownType T[ext].
func NewTextMessage(textVal, language string) *Message {
	return &Message{
		[]*Record{NewTextRecord(textVal, language)},
	}
}

// NewURIMessage returns a pointer to a Message with a single Record
// of WellKnownType U[RI].
func NewURIMessage(uriVal string) *Message {
	return &Message{
		[]*Record{NewURIRecord(uriVal)},
	}
}

// NewMediaMessage returns a pointer to a Message with a single Record
// of Media (RFC-2046) type.
//
// mimeType is something like "text/json" or "image/jpeg".
func NewMediaMessage(mimeType string, payload []byte) *Message {
	return &Message{
		[]*Record{NewMediaRecord(mimeType, payload)},
	}
}

// NewAbsoluteURIMessage returns a pointer to a Message with a single Record
// of AbsoluteURI type.
//
// AbsoluteURI means that the type of the payload for this record is
// defined by an URI resource. It is not supposed to be used to
// describe an URI. For that, use NewURIRecord().
func NewAbsoluteURIMessage(typeURI string, payload []byte) *Message {
	return &Message{
		[]*Record{NewAbsoluteURIRecord(typeURI, payload)},
	}
}

// NewExternalMessage returns a pointer to a Message with a single Record
// of NFC Forum External type.
func NewExternalMessage(extType string, payload []byte) *Message {
	return &Message{
		[]*Record{NewExternalRecord(extType, payload)},
	}
}

// Reset clears the fields of a Message and puts them to their default values.
func (m *Message) Reset() {
	m.Records = []*Record{}
}

// Returns the string representation of each of the records in the message.
func (m *Message) String() string {
	str := ""
	last := len(m.Records) - 1
	for i, r := range m.Records {
		str += r.String()
		if i != last {
			str += "\n"
		}
	}
	return str
}

// Returns a string with information about the message and its records.
func (m *Message) Inspect() string {
	str := fmt.Sprintf("NDEF Message with %d records.", len(m.Records))
	if len(m.Records) > 0 {
		str += "\n"
		for i, r := range m.Records {
			str += fmt.Sprintf("Record %d:\n", i)
			rIns := r.Inspect()
			rInsLines := strings.Split(rIns, "\n")
			for _, l := range rInsLines {
				str += "  " + l + "\n"
			}
		}
	}
	return str
}

// Unmarshal parses a byte slice into a Message. This is done by
// parsing all Records in the slice, until there are no more to parse.
//
// Returns the number of bytes processed (message length), or an error
// if something looks wrong with the message or its records.
func (m *Message) Unmarshal(buf []byte) (rLen int, err error) {
	m.Reset()
	rLen = 0
	for rLen < len(buf) {
		r := new(Record)
		recordLen, err := r.Unmarshal(buf[rLen:])
		rLen += recordLen
		if err != nil {
			return rLen, err
		}
		m.Records = append(m.Records, r)
	}

	err = m.check()
	return rLen, err
}

// Marshal provides the byte slice representation of a Message,
// which is the concatenation of the Marshaling of each of its records.
//
// Returns an error if something goes wrong.
func (m *Message) Marshal() ([]byte, error) {
	err := m.check()
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	for _, r := range m.Records {
		rBytes, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		buffer.Write(rBytes)
	}
	return buffer.Bytes(), nil
}

func (m *Message) check() error {
	return nil
}
