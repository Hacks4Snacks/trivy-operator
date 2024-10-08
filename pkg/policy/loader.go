package policy

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/policy"
	"github.com/aquasecurity/trivy/pkg/iac/policy/types"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Loader interface {
	LoadPolicies(ctx context.Context) (types.PolicyLoader, error)
}

type policyLoader struct {
	options []policy.Option
	logger  logr.Logger
	mutex   sync.RWMutex
}

func NewPolicyLoader(opts ...policy.Option) Loader {
	return &policyLoader{
		options: opts,
		logger:  ctrl.Log.WithName("policyLoader"),
	}
}

func (pl *policyLoader) LoadPolicies(ctx context.Context) (types.PolicyLoader, error) {
	pl.mutex.Lock()
	defer pl.mutex.Unlock()

	// Use the new policy loading mechanism
	policyLoader, err := policy.Load(ctx, pl.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return policyLoader, nil
}
