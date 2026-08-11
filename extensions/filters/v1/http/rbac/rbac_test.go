package rbacv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestSourceWorkloadPrincipalRoundTrip(t *testing.T) {
	want := &Source{Principals: []string{"cluster.local/ns/payments/sa/checkout"}}
	data, err := proto.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Source
	if err := proto.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(want, &got) {
		t.Fatalf("round trip = %v, want %v", &got, want)
	}
}
