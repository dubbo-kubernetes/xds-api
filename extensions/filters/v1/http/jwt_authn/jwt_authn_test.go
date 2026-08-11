package jwt_authnv1

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestClaimHeaderProtoJSONRoundTrip(t *testing.T) {
	in := &JwtProvider{
		Issuer:                "https://issuer.example",
		FromCookies:           []string{"access_token"},
		ForwardOriginalToken:  true,
		OutputPayloadToHeader: "x-jwt-payload",
		OutputClaimToHeaders: []*ClaimToHeader{{
			Claim:  "nested.group",
			Header: "x-jwt-group",
		}},
	}

	data, err := protojson.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out JwtProvider
	if err := protojson.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !out.GetForwardOriginalToken() || out.GetOutputClaimToHeaders()[0].GetHeader() != "x-jwt-group" {
		t.Fatalf("round trip = %#v", &out)
	}
}
