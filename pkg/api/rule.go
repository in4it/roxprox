package api

type Metadata struct {
	Name string `json:"name"`
}
type Rule struct {
	API      string   `json:"api"`
	Kind     string   `json:"kind"`
	Metadata Metadata `json:"metadata"`
	Spec     RuleSpec `json:"spec"`
}
type RuleSpec struct {
	Auth        RuleAuth         `json:"auth"`
	Certificate string           `json:"certificate"`
	Conditions  []RuleConditions `json:"conditions"`
	Actions     []RuleActions    `json:"actions"`
}
type RuleAuth struct {
	JwtProvider string `json:"jwtProvider" yaml:"jwtProvider"`
}
type RuleConditions struct {
	Hostname string   `json:"hostname"`
	Prefix   string   `json:"prefix"`
	Path     string   `json:"path"`
	Regex    string   `json:"regex"`
	Methods  []string `json:"methods"`
}
type RuleActions struct {
	Proxy          RuleActionsProxy          `json:"proxy"`
	DirectResponse RuleActionsDirectResponse `json:"directResponse" yaml:"directResponse"`
}
type RuleActionsProxy struct {
	Hostname         string                `json:"hostname"`
	Port             int64                 `json:"port"`
	HealthCheck      RuleActionHealthCheck `json:"healthCheck" yaml:"healthCheck"`
	EnableWebsockets bool                  `json:"enableWebsockets" yaml:"enableWebsockets"`
}

type RuleActionHealthCheck struct {
	HTTPHealthCheck    HTTPHealthCheck `json:"httpHealthCheck" yaml:"httpHealthCheck"`
	Timeout            string          `json:"timeout" yaml:"timeout"`
	Interval           string          `json:"interval" yaml:"interval"`
	HealthyThreshold   uint32          `json:"healthyThreshold" yaml:"healthyThreshold"`
	UnhealthyThreshold uint32          `json:"unhealthyThreshold" yaml:"unhealthyThreshold"`
	UnhealthyInterval  string          `json:"unhealthyInterval" yaml:"unhealthyInterval"`
}
type HTTPHealthCheck struct {
	Path string `json:"path" yaml:"path"`
}

type RuleActionsDirectResponse struct {
	Status uint32 `json:"status"`
	Body   string `json:"body"`
}
