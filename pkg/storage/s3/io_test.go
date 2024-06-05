package s3

import (
	"testing"

	"github.com/in4it/roxprox/pkg/api"
	"gopkg.in/yaml.v2"
)

func TestMultiLineYaml(t *testing.T) {
	input := "spec:\n  inlineCode: |\n    this is\n    Inline code."
	var luaFilter api.LuaFilter
	err := yaml.Unmarshal([]byte(input), &luaFilter)
	if err != nil {
		t.Errorf("error: %s", err)
	}
	if luaFilter.Spec.InlineCode != "this is\nInline code." {
		t.Errorf("inline code, wrong output: '%s'", luaFilter.Spec.InlineCode)
	}
}
