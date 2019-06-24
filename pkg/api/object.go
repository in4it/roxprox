package api

type Object struct {
	API      string   `json:"api"`
	Kind     string   `json:"kind"`
	Metadata Metadata `json:"metadata"`
	Data     interface{}
}
