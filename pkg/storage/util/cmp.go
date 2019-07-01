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
