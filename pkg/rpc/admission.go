package rpc

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// AdmissionInterceptor enforces admission completeness on the wire: a
// request carrying any field the schema does not define is rejected with
// InvalidArgument. Protobuf keeps unknown fields on decode instead of
// dropping them, so "the request struct has no field to bind it to" is a
// checkable property, not a silent one.
func AdmissionInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if m, ok := req.(proto.Message); ok {
			if err := RejectUnknown(m.ProtoReflect()); err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
		}
		return handler(ctx, req)
	}
}

// RejectUnknown walks the message and every nested message and fails on
// the first unknown field found.
func RejectUnknown(m protoreflect.Message) error {
	if len(m.GetUnknown()) > 0 {
		return fmt.Errorf("admission: %s carries a field the protocol does not define", m.Descriptor().FullName())
	}
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Kind() == protoreflect.MessageKind:
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				if err = RejectUnknown(l.Get(i).Message()); err != nil {
					return false
				}
			}
		case fd.IsMap():
			if fd.MapValue().Kind() != protoreflect.MessageKind {
				return true
			}
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				err = RejectUnknown(mv.Message())
				return err == nil
			})
			return err == nil
		case fd.Kind() == protoreflect.MessageKind:
			err = RejectUnknown(v.Message())
			return err == nil
		}
		return true
	})
	return err
}
