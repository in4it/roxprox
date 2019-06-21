package s3

import (
	"time"
)

type Config struct {
	Prefix string
	Bucket string
	Region string
}

type NotificationEntry struct {
	messageID string
}

type S3NotificationBody struct {
	Service   string    `json:"Service"`
	Event     string    `json:"Event"`
	Time      time.Time `json:"Time"`
	Bucket    string    `json:"Bucket"`
	RequestId string    `json:"RequestId"`
	HostId    string    `json:"HostId"`
}
