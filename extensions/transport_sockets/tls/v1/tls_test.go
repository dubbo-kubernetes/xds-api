package tlsv1

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestMinimumTLSVersionProtoJSONRoundTrip(t *testing.T) {
	in := &CommonTlsContext{
		TlsParams: &TlsParameters{MinProtocolVersion: TlsParameters_TLSV1_3},
	}
	data, err := protojson.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out CommonTlsContext
	if err := protojson.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.GetTlsParams().GetMinProtocolVersion() != TlsParameters_TLSV1_3 {
		t.Fatalf("round trip = %#v", &out)
	}
}
