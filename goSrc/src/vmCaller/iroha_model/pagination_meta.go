package iroha_model

import "C"
import (
	"fmt"
	"strconv"
	"time"
	pb "iroha.protocol"
	"github.com/golang/protobuf/ptypes"
	"encoding/json"
)

type TxPaginationMeta struct{
	PageSize *string
	FirstTxHash *string
	Ordering *string
	FirstTxTime *string
	LastTxTime *string
	FirstTxHeight *string
	LastTxHeight *string
}

type OrderingField struct {
	Field string `json:"field"`
	Direction string `json:"direction"`
}

func MakeTxPaginationMeta(txMeta *TxPaginationMeta) (pb.TxPaginationMeta, error) {
	TxPaginationMeta := pb.TxPaginationMeta{}
	if len(*txMeta.Ordering)!=0 {
		var ordering []OrderingField
		json.Unmarshal([]byte(*txMeta.Ordering), &ordering)
		var pb_ord = make([]*pb.Ordering_FieldOrdering, len(ordering))
		for i, p_order := range ordering {
			pb_ord[i] = &pb.Ordering_FieldOrdering{Field: pb.Field(pb.Field_value[p_order.Field]), Direction: pb.Direction(pb.Direction_value[p_order.Direction])}
		}
		order := pb.Ordering{Sequence: pb_ord}
		TxPaginationMeta.Ordering= &order
	}
	// check page size
	size, err := strconv.ParseUint(*txMeta.PageSize, 10, 32)
	if err != nil {
		return TxPaginationMeta, fmt.Errorf("Invalid value, page_size > 0")
	}else{
		TxPaginationMeta.PageSize = uint32(size)
	}
	// check firstTxTime
	if txMeta.FirstTxTime!=nil && len(*txMeta.FirstTxTime) != 0 { //check if value is passed
		firstTimeMs, err := strconv.ParseInt(*txMeta.FirstTxTime, 10, 64) //parse it
		firstTime, err1 := ptypes.TimestampProto(time.Unix(0, firstTimeMs*int64(time.Millisecond)))
		if err!=nil || err1!=nil { //set or not proper proto field
			return TxPaginationMeta, fmt.Errorf("Invalid firstTxTime value")
		}else{
			TxPaginationMeta.OptFirstTxTime = &pb.TxPaginationMeta_FirstTxTime{firstTime}
		}
	}
	// check lastTxTime
	if txMeta.LastTxTime!=nil && len(*txMeta.LastTxTime) != 0 {
		lastTimeMs, err := strconv.ParseInt(*txMeta.LastTxTime, 10, 64)
		lastTime, err1 := ptypes.TimestampProto(time.Unix(0, lastTimeMs*int64(time.Millisecond)))
		if err!=nil || err1!=nil {
			return TxPaginationMeta, fmt.Errorf("Invalid lastTxTime value")
		}else{
			TxPaginationMeta.OptLastTxTime = &pb.TxPaginationMeta_LastTxTime{lastTime}
		}
	}
	// check firstTxHeight
	if txMeta.FirstTxHeight!=nil && len(*txMeta.FirstTxHeight) != 0 {
		firstHeightInt, err := strconv.ParseUint(*txMeta.FirstTxHeight, 10, 64)
		if err!=nil {
			return TxPaginationMeta, fmt.Errorf("Invalid First tx Height value")
		}else{
			TxPaginationMeta.OptFirstTxHeight = &pb.TxPaginationMeta_FirstTxHeight{firstHeightInt}
		}
	}
	// check lastTxHeight
	if txMeta.LastTxHeight!=nil && len(*txMeta.LastTxHeight) != 0 {
		lastHeightInt, err := strconv.ParseUint(*txMeta.LastTxHeight, 10, 64)
		if err!=nil {
			return TxPaginationMeta, fmt.Errorf("Invalid lastTxHeight value")
		}else{
			TxPaginationMeta.OptLastTxHeight = &pb.TxPaginationMeta_LastTxHeight{lastHeightInt}
		}
	}
	return TxPaginationMeta, nil
}
