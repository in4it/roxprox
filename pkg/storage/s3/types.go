package s3

import (
	"time"
)

type Config struct {
	Prefix               string
	Bucket               string
	Region               string
	StorageNotifications string
}

type NotificationEntry struct {
	messageID string
}

type S3NotificationBody struct {
	Records []Records `json:"Records"`
}
type UserIdentity struct {
	PrincipalID string `json:"principalId"`
}
type RequestParameters struct {
	SourceIPAddress string `json:"sourceIPAddress"`
}
type ResponseElements struct {
	XAmzRequestID string `json:"x-amz-request-id"`
	XAmzID2       string `json:"x-amz-id-2"`
}
type OwnerIdentity struct {
	PrincipalID string `json:"principalId"`
}
type Bucket struct {
	Name          string        `json:"name"`
	OwnerIdentity OwnerIdentity `json:"ownerIdentity"`
	Arn           string        `json:"arn"`
}
type Object struct {
	Key       string `json:"key"`
	Size      int    `json:"size"`
	ETag      string `json:"eTag"`
	Sequencer string `json:"sequencer"`
}
type S3 struct {
	S3SchemaVersion string `json:"s3SchemaVersion"`
	ConfigurationID string `json:"configurationId"`
	Bucket          Bucket `json:"bucket"`
	Object          Object `json:"object"`
}
type Records struct {
	EventVersion      string            `json:"eventVersion"`
	EventSource       string            `json:"eventSource"`
	AwsRegion         string            `json:"awsRegion"`
	EventTime         time.Time         `json:"eventTime"`
	EventName         string            `json:"eventName"`
	UserIdentity      UserIdentity      `json:"userIdentity"`
	RequestParameters RequestParameters `json:"requestParameters"`
	ResponseElements  ResponseElements  `json:"responseElements"`
	S3                S3                `json:"s3"`
}
