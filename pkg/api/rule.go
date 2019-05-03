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
	Certificate string           `json:"certificate"`
	Conditions  []RuleConditions `json:"conditions"`
	Actions     []RuleActions    `json:"actions"`
}
type RuleConditions struct {
	Hostname string `json:"hostname"`
	Prefix   string `json:"prefix"`
}
type RuleActions struct {
	Proxy RuleActionsProxy `json:"proxy"`
}
type RuleActionsProxy struct {
	Hostname string `json:"hostname"`
	Port     int64  `json:"port"`
}
