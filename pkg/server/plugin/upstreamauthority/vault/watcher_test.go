package vault

import (
	"crypto/x509"
	"testing"
)

func Test_isRenewed(t *testing.T) {
	type args struct {
		updated *x509.Certificate
		current *x509.Certificate
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRenewed(tt.args.updated, tt.args.current); got != tt.want {
				t.Errorf("isRenewed() = %v, want %v", got, tt.want)
			}
		})
	}
}
