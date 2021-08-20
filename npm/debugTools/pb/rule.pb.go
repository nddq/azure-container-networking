// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.6.1
// source: rule.proto

package pb

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type SetType int32

const (
	SetType_NAMESPACE                SetType = 0
	SetType_KEYLABELOFNAMESPACE      SetType = 1
	SetType_KEYVALUELABELOFNAMESPACE SetType = 2
	SetType_KEYLABELOFPOD            SetType = 3
	SetType_KEYVALUELABELOFPOD       SetType = 4
	SetType_NAMEDPORTS               SetType = 5
	SetType_NESTEDLABELOFPOD         SetType = 6
	SetType_CIDRBLOCKS               SetType = 7
)

// Enum value maps for SetType.
var (
	SetType_name = map[int32]string{
		0: "NAMESPACE",
		1: "KEYLABELOFNAMESPACE",
		2: "KEYVALUELABELOFNAMESPACE",
		3: "KEYLABELOFPOD",
		4: "KEYVALUELABELOFPOD",
		5: "NAMEDPORTS",
		6: "NESTEDLABELOFPOD",
		7: "CIDRBLOCKS",
	}
	SetType_value = map[string]int32{
		"NAMESPACE":                0,
		"KEYLABELOFNAMESPACE":      1,
		"KEYVALUELABELOFNAMESPACE": 2,
		"KEYLABELOFPOD":            3,
		"KEYVALUELABELOFPOD":       4,
		"NAMEDPORTS":               5,
		"NESTEDLABELOFPOD":         6,
		"CIDRBLOCKS":               7,
	}
)

func (x SetType) Enum() *SetType {
	p := new(SetType)
	*p = x
	return p
}

func (x SetType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SetType) Descriptor() protoreflect.EnumDescriptor {
	return file_rule_proto_enumTypes[0].Descriptor()
}

func (SetType) Type() protoreflect.EnumType {
	return &file_rule_proto_enumTypes[0]
}

func (x SetType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SetType.Descriptor instead.
func (SetType) EnumDescriptor() ([]byte, []int) {
	return file_rule_proto_rawDescGZIP(), []int{0}
}

type Direction int32

const (
	Direction_UNDEFINED Direction = 0
	Direction_EGRESS    Direction = 1
	Direction_INGRESS   Direction = 2
)

// Enum value maps for Direction.
var (
	Direction_name = map[int32]string{
		0: "UNDEFINED",
		1: "EGRESS",
		2: "INGRESS",
	}
	Direction_value = map[string]int32{
		"UNDEFINED": 0,
		"EGRESS":    1,
		"INGRESS":   2,
	}
)

func (x Direction) Enum() *Direction {
	p := new(Direction)
	*p = x
	return p
}

func (x Direction) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Direction) Descriptor() protoreflect.EnumDescriptor {
	return file_rule_proto_enumTypes[1].Descriptor()
}

func (Direction) Type() protoreflect.EnumType {
	return &file_rule_proto_enumTypes[1]
}

func (x Direction) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Direction.Descriptor instead.
func (Direction) EnumDescriptor() ([]byte, []int) {
	return file_rule_proto_rawDescGZIP(), []int{1}
}

type RuleResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Chain         string                  `protobuf:"bytes,1,opt,name=Chain,proto3" json:"Chain,omitempty"`
	SrcList       []*RuleResponse_SetInfo `protobuf:"bytes,2,rep,name=SrcList,proto3" json:"SrcList,omitempty"`
	DstList       []*RuleResponse_SetInfo `protobuf:"bytes,3,rep,name=DstList,proto3" json:"DstList,omitempty"`
	Protocol      string                  `protobuf:"bytes,4,opt,name=Protocol,proto3" json:"Protocol,omitempty"`
	DPort         int32                   `protobuf:"varint,5,opt,name=DPort,proto3" json:"DPort,omitempty"`
	SPort         int32                   `protobuf:"varint,6,opt,name=SPort,proto3" json:"SPort,omitempty"`
	Allowed       bool                    `protobuf:"varint,7,opt,name=Allowed,proto3" json:"Allowed,omitempty"`
	Direction     Direction               `protobuf:"varint,8,opt,name=Direction,proto3,enum=pb.Direction" json:"Direction,omitempty"`
	UnsortedIpset map[string]string       `protobuf:"bytes,9,rep,name=UnsortedIpset,proto3" json:"UnsortedIpset,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Description   string                  `protobuf:"bytes,10,opt,name=Description,proto3" json:"Description,omitempty"`
}

func (x *RuleResponse) Reset() {
	*x = RuleResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rule_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RuleResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleResponse) ProtoMessage() {}

func (x *RuleResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rule_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleResponse.ProtoReflect.Descriptor instead.
func (*RuleResponse) Descriptor() ([]byte, []int) {
	return file_rule_proto_rawDescGZIP(), []int{0}
}

func (x *RuleResponse) GetChain() string {
	if x != nil {
		return x.Chain
	}
	return ""
}

func (x *RuleResponse) GetSrcList() []*RuleResponse_SetInfo {
	if x != nil {
		return x.SrcList
	}
	return nil
}

func (x *RuleResponse) GetDstList() []*RuleResponse_SetInfo {
	if x != nil {
		return x.DstList
	}
	return nil
}

func (x *RuleResponse) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *RuleResponse) GetDPort() int32 {
	if x != nil {
		return x.DPort
	}
	return 0
}

func (x *RuleResponse) GetSPort() int32 {
	if x != nil {
		return x.SPort
	}
	return 0
}

func (x *RuleResponse) GetAllowed() bool {
	if x != nil {
		return x.Allowed
	}
	return false
}

func (x *RuleResponse) GetDirection() Direction {
	if x != nil {
		return x.Direction
	}
	return Direction_UNDEFINED
}

func (x *RuleResponse) GetUnsortedIpset() map[string]string {
	if x != nil {
		return x.UnsortedIpset
	}
	return nil
}

func (x *RuleResponse) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

type RuleResponse_SetInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type          SetType  `protobuf:"varint,1,opt,name=Type,proto3,enum=pb.SetType" json:"Type,omitempty"`
	Name          string   `protobuf:"bytes,2,opt,name=Name,proto3" json:"Name,omitempty"`
	HashedSetName string   `protobuf:"bytes,3,opt,name=HashedSetName,proto3" json:"HashedSetName,omitempty"`
	Contents      []string `protobuf:"bytes,4,rep,name=Contents,proto3" json:"Contents,omitempty"`
	Included      bool     `protobuf:"varint,5,opt,name=Included,proto3" json:"Included,omitempty"`
}

func (x *RuleResponse_SetInfo) Reset() {
	*x = RuleResponse_SetInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rule_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RuleResponse_SetInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleResponse_SetInfo) ProtoMessage() {}

func (x *RuleResponse_SetInfo) ProtoReflect() protoreflect.Message {
	mi := &file_rule_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleResponse_SetInfo.ProtoReflect.Descriptor instead.
func (*RuleResponse_SetInfo) Descriptor() ([]byte, []int) {
	return file_rule_proto_rawDescGZIP(), []int{0, 0}
}

func (x *RuleResponse_SetInfo) GetType() SetType {
	if x != nil {
		return x.Type
	}
	return SetType_NAMESPACE
}

func (x *RuleResponse_SetInfo) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RuleResponse_SetInfo) GetHashedSetName() string {
	if x != nil {
		return x.HashedSetName
	}
	return ""
}

func (x *RuleResponse_SetInfo) GetContents() []string {
	if x != nil {
		return x.Contents
	}
	return nil
}

func (x *RuleResponse_SetInfo) GetIncluded() bool {
	if x != nil {
		return x.Included
	}
	return false
}

var File_rule_proto protoreflect.FileDescriptor

var file_rule_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x02, 0x70, 0x62,
	0x22, 0xe9, 0x04, 0x0a, 0x0c, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x12, 0x32, 0x0a, 0x07, 0x53, 0x72, 0x63, 0x4c, 0x69,
	0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70, 0x62, 0x2e, 0x52, 0x75,
	0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x53, 0x65, 0x74, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x07, 0x53, 0x72, 0x63, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x07, 0x44,
	0x73, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70,
	0x62, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x53,
	0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x07, 0x44, 0x73, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x12,
	0x1a, 0x0a, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x44,
	0x50, 0x6f, 0x72, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x44, 0x50, 0x6f, 0x72,
	0x74, 0x12, 0x14, 0x0a, 0x05, 0x53, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x05, 0x53, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x41, 0x6c, 0x6c, 0x6f, 0x77,
	0x65, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x65,
	0x64, 0x12, 0x2b, 0x0a, 0x09, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x0d, 0x2e, 0x70, 0x62, 0x2e, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x09, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x49,
	0x0a, 0x0d, 0x55, 0x6e, 0x73, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x49, 0x70, 0x73, 0x65, 0x74, 0x18,
	0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x70, 0x62, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e, 0x55, 0x6e, 0x73, 0x6f, 0x72, 0x74, 0x65, 0x64,
	0x49, 0x70, 0x73, 0x65, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0d, 0x55, 0x6e, 0x73, 0x6f,
	0x72, 0x74, 0x65, 0x64, 0x49, 0x70, 0x73, 0x65, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x65, 0x73,
	0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x9c, 0x01, 0x0a, 0x07,
	0x53, 0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1f, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0b, 0x2e, 0x70, 0x62, 0x2e, 0x53, 0x65, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x4e, 0x61, 0x6d, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x24, 0x0a, 0x0d,
	0x48, 0x61, 0x73, 0x68, 0x65, 0x64, 0x53, 0x65, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0d, 0x48, 0x61, 0x73, 0x68, 0x65, 0x64, 0x53, 0x65, 0x74, 0x4e, 0x61,
	0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x1a,
	0x0a, 0x08, 0x49, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x08, 0x49, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x64, 0x1a, 0x40, 0x0a, 0x12, 0x55, 0x6e,
	0x73, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x49, 0x70, 0x73, 0x65, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x2a, 0xb0, 0x01, 0x0a,
	0x07, 0x53, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x4e, 0x41, 0x4d, 0x45,
	0x53, 0x50, 0x41, 0x43, 0x45, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x4b, 0x45, 0x59, 0x4c, 0x41,
	0x42, 0x45, 0x4c, 0x4f, 0x46, 0x4e, 0x41, 0x4d, 0x45, 0x53, 0x50, 0x41, 0x43, 0x45, 0x10, 0x01,
	0x12, 0x1c, 0x0a, 0x18, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x4c, 0x41, 0x42, 0x45,
	0x4c, 0x4f, 0x46, 0x4e, 0x41, 0x4d, 0x45, 0x53, 0x50, 0x41, 0x43, 0x45, 0x10, 0x02, 0x12, 0x11,
	0x0a, 0x0d, 0x4b, 0x45, 0x59, 0x4c, 0x41, 0x42, 0x45, 0x4c, 0x4f, 0x46, 0x50, 0x4f, 0x44, 0x10,
	0x03, 0x12, 0x16, 0x0a, 0x12, 0x4b, 0x45, 0x59, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x4c, 0x41, 0x42,
	0x45, 0x4c, 0x4f, 0x46, 0x50, 0x4f, 0x44, 0x10, 0x04, 0x12, 0x0e, 0x0a, 0x0a, 0x4e, 0x41, 0x4d,
	0x45, 0x44, 0x50, 0x4f, 0x52, 0x54, 0x53, 0x10, 0x05, 0x12, 0x14, 0x0a, 0x10, 0x4e, 0x45, 0x53,
	0x54, 0x45, 0x44, 0x4c, 0x41, 0x42, 0x45, 0x4c, 0x4f, 0x46, 0x50, 0x4f, 0x44, 0x10, 0x06, 0x12,
	0x0e, 0x0a, 0x0a, 0x43, 0x49, 0x44, 0x52, 0x42, 0x4c, 0x4f, 0x43, 0x4b, 0x53, 0x10, 0x07, 0x2a,
	0x33, 0x0a, 0x09, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x0d, 0x0a, 0x09,
	0x55, 0x4e, 0x44, 0x45, 0x46, 0x49, 0x4e, 0x45, 0x44, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x45,
	0x47, 0x52, 0x45, 0x53, 0x53, 0x10, 0x01, 0x12, 0x0b, 0x0a, 0x07, 0x49, 0x4e, 0x47, 0x52, 0x45,
	0x53, 0x53, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rule_proto_rawDescOnce sync.Once
	file_rule_proto_rawDescData = file_rule_proto_rawDesc
)

func file_rule_proto_rawDescGZIP() []byte {
	file_rule_proto_rawDescOnce.Do(func() {
		file_rule_proto_rawDescData = protoimpl.X.CompressGZIP(file_rule_proto_rawDescData)
	})
	return file_rule_proto_rawDescData
}

var file_rule_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_rule_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_rule_proto_goTypes = []interface{}{
	(SetType)(0),                 // 0: pb.SetType
	(Direction)(0),               // 1: pb.Direction
	(*RuleResponse)(nil),         // 2: pb.RuleResponse
	(*RuleResponse_SetInfo)(nil), // 3: pb.RuleResponse.SetInfo
	nil,                          // 4: pb.RuleResponse.UnsortedIpsetEntry
}
var file_rule_proto_depIdxs = []int32{
	3, // 0: pb.RuleResponse.SrcList:type_name -> pb.RuleResponse.SetInfo
	3, // 1: pb.RuleResponse.DstList:type_name -> pb.RuleResponse.SetInfo
	1, // 2: pb.RuleResponse.Direction:type_name -> pb.Direction
	4, // 3: pb.RuleResponse.UnsortedIpset:type_name -> pb.RuleResponse.UnsortedIpsetEntry
	0, // 4: pb.RuleResponse.SetInfo.Type:type_name -> pb.SetType
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_rule_proto_init() }
func file_rule_proto_init() {
	if File_rule_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rule_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RuleResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rule_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RuleResponse_SetInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_rule_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_rule_proto_goTypes,
		DependencyIndexes: file_rule_proto_depIdxs,
		EnumInfos:         file_rule_proto_enumTypes,
		MessageInfos:      file_rule_proto_msgTypes,
	}.Build()
	File_rule_proto = out.File
	file_rule_proto_rawDesc = nil
	file_rule_proto_goTypes = nil
	file_rule_proto_depIdxs = nil
}
