package safebrowsing

import (
	"time"

	"github.com/golang/protobuf/proto"
)

type batchGetHashListsResponse struct {
	HashLists []*wireHashList `protobuf:"bytes,1,rep,name=hash_lists,json=hashLists,proto3"`
}

func (m *batchGetHashListsResponse) Reset()         { *m = batchGetHashListsResponse{} }
func (m *batchGetHashListsResponse) String() string { return proto.CompactTextString(m) }
func (*batchGetHashListsResponse) ProtoMessage()    {}

type wireHashList struct {
	Name                string                     `protobuf:"bytes,1,opt,name=name,proto3"`
	Version             []byte                     `protobuf:"bytes,2,opt,name=version,proto3"`
	PartialUpdate       bool                       `protobuf:"varint,3,opt,name=partial_update,json=partialUpdate,proto3"`
	AdditionsFourBytes  *riceDeltaEncoded32Bit     `protobuf:"bytes,4,opt,name=additions_four_bytes,json=additionsFourBytes,proto3"`
	CompressedRemovals  *riceDeltaEncoded32Bit     `protobuf:"bytes,5,opt,name=compressed_removals,json=compressedRemovals,proto3"`
	MinimumWaitDuration *wireDuration              `protobuf:"bytes,6,opt,name=minimum_wait_duration,json=minimumWaitDuration,proto3"`
	SHA256Checksum      []byte                     `protobuf:"bytes,7,opt,name=sha256_checksum,json=sha256Checksum,proto3"`
}

func (m *wireHashList) Reset()         { *m = wireHashList{} }
func (m *wireHashList) String() string { return proto.CompactTextString(m) }
func (*wireHashList) ProtoMessage()    {}

type riceDeltaEncoded32Bit struct {
	FirstValue    uint32 `protobuf:"varint,1,opt,name=first_value,json=firstValue,proto3"`
	RiceParameter int32  `protobuf:"varint,2,opt,name=rice_parameter,json=riceParameter,proto3"`
	EntriesCount  int32  `protobuf:"varint,3,opt,name=entries_count,json=entriesCount,proto3"`
	EncodedData   []byte `protobuf:"bytes,4,opt,name=encoded_data,json=encodedData,proto3"`
}

func (m *riceDeltaEncoded32Bit) Reset()         { *m = riceDeltaEncoded32Bit{} }
func (m *riceDeltaEncoded32Bit) String() string { return proto.CompactTextString(m) }
func (*riceDeltaEncoded32Bit) ProtoMessage()    {}

type wireDuration struct {
	Seconds int64 `protobuf:"varint,1,opt,name=seconds,proto3"`
	Nanos   int32 `protobuf:"varint,2,opt,name=nanos,proto3"`
}

func (m *wireDuration) Reset()         { *m = wireDuration{} }
func (m *wireDuration) String() string { return proto.CompactTextString(m) }
func (*wireDuration) ProtoMessage()    {}

func (m *wireDuration) Duration() time.Duration {
	return time.Duration(m.Seconds)*time.Second + time.Duration(m.Nanos)
}

type searchHashesResponse struct {
	FullHashes    []*wireFullHash `protobuf:"bytes,1,rep,name=full_hashes,json=fullHashes,proto3"`
	CacheDuration *wireDuration   `protobuf:"bytes,2,opt,name=cache_duration,json=cacheDuration,proto3"`
}

func (m *searchHashesResponse) Reset()         { *m = searchHashesResponse{} }
func (m *searchHashesResponse) String() string { return proto.CompactTextString(m) }
func (*searchHashesResponse) ProtoMessage()    {}

type wireFullHash struct {
	FullHash        []byte                `protobuf:"bytes,1,opt,name=full_hash,json=fullHash,proto3"`
	FullHashDetails []*wireFullHashDetail `protobuf:"bytes,2,rep,name=full_hash_details,json=fullHashDetails,proto3"`
}

func (m *wireFullHash) Reset()         { *m = wireFullHash{} }
func (m *wireFullHash) String() string { return proto.CompactTextString(m) }
func (*wireFullHash) ProtoMessage()    {}

type wireFullHashDetail struct {
	ThreatType int32   `protobuf:"varint,1,opt,name=threat_type,json=threatType,proto3"`
	Attributes []int32 `protobuf:"varint,2,rep,packed,name=attributes,proto3"`
}

func (m *wireFullHashDetail) Reset()         { *m = wireFullHashDetail{} }
func (m *wireFullHashDetail) String() string { return proto.CompactTextString(m) }
func (*wireFullHashDetail) ProtoMessage()    {}

func threatTypeName(value int32) string {
	switch value {
	case 1:
		return string(ThreatTypeMalware)
	case 2:
		return string(ThreatTypeSocialEngineering)
	case 3:
		return string(ThreatTypeUnwantedSoftware)
	case 4:
		return string(ThreatTypePotentiallyHarmfulApplication)
	default:
		return string(ThreatTypeUnspecified)
	}
}

func threatAttributeName(value int32) string {
	switch value {
	case 1:
		return "CANARY"
	case 2:
		return "FRAME_ONLY"
	default:
		return "THREAT_ATTRIBUTE_UNSPECIFIED"
	}
}
