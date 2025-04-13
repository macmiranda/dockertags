package docker

import (
	"context"
)

type MockClient struct {
	Tags []string
	Err  error
}

func (m *MockClient) ListTags(ctx context.Context, repository string) ([]string, error) {
	return m.Tags, m.Err
}
