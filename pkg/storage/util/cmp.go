package util

import (
	"github.com/google/go-cmp/cmp"
	"github.com/in4it/roxprox/pkg/api"
)

func ConditionExists(conditions []api.RuleConditions, condition api.RuleConditions) bool {
	for _, v := range conditions {
		if cmp.Equal(v, condition) {
			return true
		}
	}
	return false
}

func NameExistsInCache(cache map[string]*api.Object, name string) bool {
	for _, v := range cache {
		if v.Metadata.Name == name {
			return true
		}
	}
	return false
}

func CmpActions(a1, a2 []api.RuleActions) bool {
	if len(a1) != len(a2) {
		return false
	}
	for k := range a1 {
		if a1[k] != a2[k] {
			return false
		}
	}
	return true
}
