package cmd

import (
	"testing"
)

func TestValidateImageName(t *testing.T) {
	tests := []struct {
		name    string
		image   string
		wantErr bool
	}{
		{
			name:    "valid simple image",
			image:   "alpine",
			wantErr: false,
		},
		{
			name:    "valid image with tag",
			image:   "alpine:latest",
			wantErr: false,
		},
		{
			name:    "valid image with digest",
			image:   "alpine@sha256:abc123",
			wantErr: false,
		},
		{
			name:    "valid full registry path",
			image:   "ghcr.io/mchmarny/vimp:v1.0.0",
			wantErr: false,
		},
		{
			name:    "valid image with underscores",
			image:   "my_repo/my_image:v1",
			wantErr: false,
		},
		{
			name:    "empty image",
			image:   "",
			wantErr: true,
		},
		{
			name:    "image with shell injection",
			image:   "alpine;rm -rf /",
			wantErr: true,
		},
		{
			name:    "image with command substitution",
			image:   "alpine$(whoami)",
			wantErr: true,
		},
		{
			name:    "image with backticks",
			image:   "alpine`whoami`",
			wantErr: true,
		},
		{
			name:    "image with pipe",
			image:   "alpine|cat /etc/passwd",
			wantErr: true,
		},
		{
			name:    "image with path traversal",
			image:   "alpine/../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "image with spaces",
			image:   "alpine latest",
			wantErr: true,
		},
		{
			name:    "image starting with dash",
			image:   "-alpine",
			wantErr: true,
		},
		{
			name:    "image too long",
			image:   string(make([]byte, 501)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateImageName(tt.image)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateImageName(%q) error = %v, wantErr %v", tt.image, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeImageName(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{
			name:  "simple image",
			image: "alpine",
			want:  "alpine",
		},
		{
			name:  "image with tag",
			image: "alpine:latest",
			want:  "alpine_latest",
		},
		{
			name:  "image with digest",
			image: "alpine@sha256:abc",
			want:  "alpine_sha256_abc",
		},
		{
			name:  "full registry path",
			image: "ghcr.io/repo/image:v1",
			want:  "ghcr.io_repo_image_v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeImageName(tt.image)
			if got != tt.want {
				t.Errorf("sanitizeImageName(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}
