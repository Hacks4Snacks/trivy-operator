package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy/pkg/iac/severity"

	"github.com/aquasecurity/trivy/pkg/iac/policy"
	"github.com/aquasecurity/trivy/pkg/iac/policy/types"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"

	"github.com/go-logr/logr"
	"github.com/liamg/memoryfs"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	PoliciesNotFoundError = "failed to load rego policies from [externalPolicies]: stat externalPolicies: file does not exist"
)

const (
	kindAny                   = "*"
	kindWorkload              = "Workload"
	inputFolder               = "inputs"
	policiesFolder            = "externalPolicies"
	regoExt                   = "rego"
	yamlExt                   = "yaml"
	externalPoliciesNamespace = "trivyoperator"
)

type Policies struct {
	data           map[string]string
	log            logr.Logger
	cac            configauditreport.ConfigAuditConfig
	clusterVersion string
	policyLoader   Loader
}

func NewPolicies(data map[string]string, cac configauditreport.ConfigAuditConfig, log logr.Logger, pl Loader, serverVersion string) *Policies {
	return &Policies{
		data:           data,
		log:            log,
		cac:            cac,
		policyLoader:   pl,
		clusterVersion: serverVersion,
	}
}

// Eval evaluates Rego policies with Kubernetes resource client.Object as input.
func (p *Policies) Eval(ctx context.Context, resource client.Object, inputs ...[]byte) (scan.Results, error) {
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind

	// Use the new policy loading mechanism
	policyFS, err := p.loadPolicies(ctx, resourceKind)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies for kind %s: %w", resourceKind, err)
	}

	// Create in-memory filesystem for inputs
	memfs := memoryfs.New()
	inputResource, err := resourceBytes(resource, inputs)
	if err != nil {
		return nil, err
	}
	// Write input resource to the in-memory filesystem
	if err := memfs.WriteFile(path.Join(inputFolder, "resource.yaml"), inputResource, 0644); err != nil {
		return nil, err
	}

	// Create scanner options
	so := []types.ScannerOption{
		types.ScannerWithPolicyFS(policyFS),
	}

	// Create a new scanner with the updated options
	scanner := kubernetes.NewScanner(so...)
	scanResult, err := scanner.ScanFS(ctx, memfs, inputFolder)
	if err != nil {
		return nil, err
	}
	if scanResult == nil {
		return nil, fmt.Errorf("failed to run policy checks on resources")
	}
	return scanResult, nil
}

func (p *Policies) loadPolicies(ctx context.Context, kind string) (fs.FS, error) {
	// Load policies using the new policy loader
	policyOptions := []policy.Option{
		policy.WithDisabledBuiltInPolicies(!p.cac.GetUseBuiltinRegoPolicies()),
		policy.WithPolicyPaths([]string{policiesFolder}),
		policy.WithDataPaths([]string{}),
		policy.WithFileSystem(memoryfs.New()),
	}

	policyFS, err := policy.Load(ctx, policyOptions...)
	if err != nil {
		return nil, err
	}
	return policyFS, nil
}

func resourceBytes(resource client.Object, inputs [][]byte) ([]byte, error) {
	var inputResource []byte
	var err error
	if len(inputs) > 0 {
		inputResource = inputs[0]
	} else {
		if jsonManifest, ok := resource.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]; ok {
			inputResource = []byte(jsonManifest) // required for outdated-api when k8s convert resources
		} else {
			inputResource, err = json.Marshal(resource)
			if err != nil {
				return nil, err
			}
		}
	}
	return inputResource, nil
}

// GetResultID returns the result ID found in aliases (legacy) otherwise use AVDID
func (r *Policies) GetResultID(result scan.Result) string {
	id := result.Rule().AVDID
	if len(result.Rule().Aliases) > 0 {
		id = result.Rule().Aliases[0]
	}
	return id
}

func (r *Policies) HasSeverity(resultSeverity severity.Severity) bool {
	defaultSeverity := r.cac.GetSeverity()
	if defaultSeverity == "" {
		defaultSeverity = trivy.DefaultSeverity
	}
	return strings.Contains(defaultSeverity, string(resultSeverity))
}
