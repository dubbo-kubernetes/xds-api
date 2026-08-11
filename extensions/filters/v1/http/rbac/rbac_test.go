package rbacv1

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestExtendedRBACProtoJSONRoundTrip(t *testing.T) {
	in := &RBAC{
		Action:     RBAC_DENY,
		Shadow:     true,
		PolicyName: "deny-admin",
		Rules: []*Rule{{
			Sources: []*Source{{
				Principals:     []string{"cluster.local/ns/default/sa/client"},
				RemoteIpBlocks: []string{"203.0.113.0/24"},
			}},
			Operations: []*Operation{{
				Ports:   []string{"8080"},
				Methods: []string{"POST"},
				Paths:   []string{"/admin/*"},
			}},
		}},
	}

	data, err := protojson.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out RBAC
	if err := protojson.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.GetShadow() || out.GetPolicyName() != "deny-admin" ||
		out.GetRules()[0].GetOperations()[0].GetMethods()[0] != "POST" {
		t.Fatalf("round trip = %#v", &out)
	}
}
