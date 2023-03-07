package utils

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func ToGRPCTime(v string) *timestamppb.Timestamp {
	t, _ := time.Parse("2006-01-02T15:04:05.999999Z", v)
	return timestamppb.New(t)
}
