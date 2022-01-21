package api

type LuaFilter struct {
	API      string        `json:"api" yaml:"api"`
	Kind     string        `json:"kind" yaml:"kind"`
	Metadata Metadata      `json:"metadata" yaml:"metadata"`
	Spec     LuaFilterSpec `json:"spec" yaml:"spec"`
}
type LuaFilterSpec struct {
	InlineCode string   `json:"inline_code" yaml:"inlineCode"`
	Listener   Listener `json:"listener"`
}
