package rpc_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
)

// nodeDescriptor is a message with every shape RejectUnknown walks. It
// has a nested message, a list of messages, maps of messages and of
// scalars, and scalar fields.
//
//	message Node {
//	  Node child = 1;
//	  repeated Node items = 2;
//	  map<string, string> labels = 3;
//	  map<string, Node> children = 4;
//	  repeated string tags = 5;
//	  string name = 6;
//	}
func nodeDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	field := func(name string, num int32, label descriptorpb.FieldDescriptorProto_Label, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(num), Label: label.Enum(), Type: typ.Enum()}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	const (
		opt = descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		rep = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
		msg = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
		str = descriptorpb.FieldDescriptorProto_TYPE_STRING
	)
	entry := func(name string, value *descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{
			Name:    proto.String(name),
			Field:   []*descriptorpb.FieldDescriptorProto{field("key", 1, opt, str, ""), value},
			Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
		}
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("rpc_admission_test.proto"),
		Package: proto.String("rpctest"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Node"),
			Field: []*descriptorpb.FieldDescriptorProto{
				field("child", 1, opt, msg, ".rpctest.Node"),
				field("items", 2, rep, msg, ".rpctest.Node"),
				field("labels", 3, rep, msg, ".rpctest.Node.LabelsEntry"),
				field("children", 4, rep, msg, ".rpctest.Node.ChildrenEntry"),
				field("tags", 5, rep, str, ""),
				field("name", 6, opt, str, ""),
			},
			NestedType: []*descriptorpb.DescriptorProto{
				entry("LabelsEntry", field("value", 2, opt, str, "")),
				entry("ChildrenEntry", field("value", 2, opt, msg, ".rpctest.Node")),
			},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fd.Messages().ByName("Node")
}

// RejectUnknown finds a smuggled field at any depth, in the message
// itself, a nested message, any item of a list, or a map value.
func TestRejectUnknown(t *testing.T) {
	md := nodeDescriptor(t)
	fields := func(m protoreflect.Message, name string) protoreflect.FieldDescriptor {
		return m.Descriptor().Fields().ByName(protoreflect.Name(name))
	}
	// node builds a Node, with field 99 smuggled in when dirty.
	node := func(dirty bool) protoreflect.Message {
		m := dynamicpb.NewMessage(md)
		m.Set(fields(m, "name"), protoreflect.ValueOfString("n"))
		if dirty {
			b := protowire.AppendTag(nil, 99, protowire.BytesType)
			m.SetUnknown(protowire.AppendBytes(b, []byte("evil")))
		}
		return m
	}
	withChild := func(parent, child protoreflect.Message) protoreflect.Message {
		parent.Set(fields(parent, "child"), protoreflect.ValueOfMessage(child))
		return parent
	}
	withItems := func(parent protoreflect.Message, items ...protoreflect.Message) protoreflect.Message {
		l := parent.Mutable(fields(parent, "items")).List()
		for _, it := range items {
			l.Append(protoreflect.ValueOfMessage(it))
		}
		return parent
	}
	withChildren := func(parent protoreflect.Message, kids map[string]protoreflect.Message) protoreflect.Message {
		mp := parent.Mutable(fields(parent, "children")).Map()
		for k, v := range kids {
			mp.Set(protoreflect.ValueOfString(k).MapKey(), protoreflect.ValueOfMessage(v))
		}
		return parent
	}
	withScalars := func(parent protoreflect.Message) protoreflect.Message {
		parent.Mutable(fields(parent, "labels")).Map().Set(protoreflect.ValueOfString("a").MapKey(), protoreflect.ValueOfString("b"))
		parent.Mutable(fields(parent, "tags")).List().Append(protoreflect.ValueOfString("t"))
		return parent
	}

	cases := []struct {
		name    string
		m       protoreflect.Message
		wantErr bool
	}{
		{name: "an empty message is admitted", m: dynamicpb.NewMessage(md)},
		{name: "every shape, all clean, is admitted",
			m: withScalars(withChildren(withItems(withChild(node(false), node(false)), node(false), node(false)), map[string]protoreflect.Message{"x": node(false)}))},
		{name: "an unknown field at the top is refused", m: node(true), wantErr: true},
		{name: "an unknown field in a nested message is refused", m: withChild(node(false), node(true)), wantErr: true},
		{name: "an unknown field in a later list item is refused", m: withItems(node(false), node(false), node(true)), wantErr: true},
		{name: "an unknown field in a map value is refused", m: withChildren(node(false), map[string]protoreflect.Message{"x": node(true)}), wantErr: true},
		{name: "an unknown field three levels down is refused",
			m:       withChild(node(false), withItems(node(false), withChildren(node(false), map[string]protoreflect.Message{"deep": node(true)}))),
			wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rpc.RejectUnknown(tc.m)
			if (err != nil) != tc.wantErr {
				t.Fatalf("RejectUnknown = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "rpctest.Node") {
				t.Fatalf("err = %v, want it to name the message", err)
			}
		})
	}
}

// The interceptor refuses a smuggled field before the handler runs, and
// passes anything else through untouched, even a request that is not a
// protobuf message.
func TestAdmissionInterceptor(t *testing.T) {
	md := nodeDescriptor(t)
	dirty := dynamicpb.NewMessage(md)
	dirty.SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	cases := []struct {
		name        string
		req         any
		wantCode    codes.Code
		wantHandled bool
	}{
		{name: "a clean message reaches the handler", req: dynamicpb.NewMessage(md), wantCode: codes.OK, wantHandled: true},
		{name: "a request that is not a message reaches the handler", req: "raw", wantCode: codes.OK, wantHandled: true},
		{name: "a smuggled field is InvalidArgument", req: dirty, wantCode: codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handled := false
			resp, err := rpc.AdmissionInterceptor()(context.Background(), tc.req, nil, func(_ context.Context, req any) (any, error) {
				handled = true
				return req, nil
			})
			if status.Code(err) != tc.wantCode || handled != tc.wantHandled {
				t.Fatalf("interceptor = %v (handled %v), want %v (handled %v)", err, handled, tc.wantCode, tc.wantHandled)
			}
			if tc.wantHandled && resp != tc.req {
				t.Fatalf("response = %v, want the handler's", resp)
			}
		})
	}
}

// recvStream hands out its messages in order, then io.EOF or err.
type recvStream struct {
	grpc.ServerStream // only RecvMsg is used
	msgs              []proto.Message
	err               error
}

func (s *recvStream) RecvMsg(m any) error {
	if len(s.msgs) == 0 {
		if s.err != nil {
			return s.err
		}
		return io.EOF
	}
	next := s.msgs[0]
	s.msgs = s.msgs[1:]
	if pm, ok := m.(proto.Message); ok {
		proto.Merge(pm, next)
	}
	return nil
}

// The stream interceptor checks every message the handler receives, not
// only the first, and passes the stream's own errors through.
func TestAdmissionStreamInterceptor(t *testing.T) {
	md := nodeDescriptor(t)
	clean := func() proto.Message { return dynamicpb.NewMessage(md) }
	dirty := func() proto.Message {
		m := dynamicpb.NewMessage(md)
		m.SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
		return m
	}
	errBroken := errors.New("transport is closing")
	cases := []struct {
		name     string
		msgs     []proto.Message
		err      error // what the stream answers after its messages
		raw      bool  // the handler receives into a value that is not a message
		want     codes.Code
		wantErr  error // when set, the handler's error is this one, unchanged
		wantRead int
	}{
		{name: "every clean message reaches the handler, then EOF", msgs: []proto.Message{clean(), clean(), clean()},
			wantErr: io.EOF, wantRead: 3},
		{name: "an unknown field on the first message is InvalidArgument", msgs: []proto.Message{dirty(), clean()},
			want: codes.InvalidArgument},
		{name: "an unknown field on a later message is InvalidArgument", msgs: []proto.Message{clean(), clean(), dirty()},
			want: codes.InvalidArgument, wantRead: 2},
		{name: "the stream's own error passes through", msgs: []proto.Message{clean()}, err: errBroken,
			wantErr: errBroken, wantRead: 1},
		{name: "a value that is not a message is not checked", msgs: []proto.Message{dirty()}, raw: true,
			wantErr: io.EOF, wantRead: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			read := 0
			handler := func(_ any, ss grpc.ServerStream) error {
				for {
					var err error
					if tc.raw {
						var s string
						err = ss.RecvMsg(&s)
					} else {
						err = ss.RecvMsg(dynamicpb.NewMessage(md))
					}
					if err != nil {
						return err
					}
					read++
				}
			}
			err := rpc.AdmissionStreamInterceptor()(nil, &recvStream{msgs: tc.msgs, err: tc.err}, nil, handler)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("interceptor = %v, want %v", err, tc.wantErr)
				}
			} else if status.Code(err) != tc.want {
				t.Fatalf("interceptor = %v, want %v", err, tc.want)
			}
			if read != tc.wantRead {
				t.Fatalf("the handler received %d messages, want %d", read, tc.wantRead)
			}
		})
	}
}

// smuggle adds field 99 to m, as a caller shaping a workload would.
func smuggle[M proto.Message](m M) M {
	b := protowire.AppendTag(nil, 99, protowire.BytesType)
	m.ProtoReflect().SetUnknown(protowire.AppendBytes(b, []byte("evil")))
	return m
}

// A Watch request is checked like any other. It used to skip the check,
// since only unary calls had an admission interceptor.
func TestWatchAdmission(t *testing.T) {
	h := newHarness(t, core.TierCheckpoint)
	if _, err := h.client.Clone(context.Background(), &grantv1.CloneRequest{
		GrantJwt: jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", Tenant: "acme"}),
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		req  *emptypb.Empty
		want codes.Code
	}{
		{name: "a clean watch streams status", req: &emptypb.Empty{}, want: codes.OK},
		{name: "a watch with an unknown field is InvalidArgument", req: smuggle(&emptypb.Empty{}), want: codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := h.client.Watch(ctx, tc.req)
			if err == nil {
				_, err = s.Recv()
			}
			if status.Code(err) != tc.want {
				t.Fatalf("watch = %v, want %v", err, tc.want)
			}
		})
	}
}
