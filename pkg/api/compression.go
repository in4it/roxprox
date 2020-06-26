package api

type Compression struct {
	API      string          `json:"api" yaml:"api"`
	Kind     string          `json:"kind" yaml:"kind"`
	Metadata Metadata        `json:"metadata" yaml:"metadata"`
	Spec     CompressionSpec `json:"spec" yaml:"spec"`
}
type CompressionSpec struct {
	Type                string   `json:"type" yaml:"type"`
	ContentLength       uint32   `json:"contentLength" yaml:"contentLength"`
	ContentType         []string `json:"contentType" yaml:"contentType"`
	DisableOnEtagHeader bool     `json:"disableOnEtagHeader" yaml:"disableOnEtagHeader"`
}
