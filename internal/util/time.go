package util

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ToGRPCTime converts string to gRPC timestamp.
func ToGRPCTime(v interface{}) *timestamppb.Timestamp {
	if v == nil {
		return nil
	}

	s, ok := v.(string)
	if !ok {
		return nil
	}

	t, err := time.Parse("2006-01-02T15:04:05.999999Z", s)
	if err != nil {
		return nil
	}
	return timestamppb.New(t)
}
