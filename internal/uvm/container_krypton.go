package uvm

import (
	"context"
	"github.com/Microsoft/hcsshim/internal/hcs/schema1"
	hcsschema "github.com/Microsoft/hcsshim/internal/hcs/schema2"

	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/pkg/errors"
)

// KryptonContainer implements the cow.Container interface.
type KryptonContainer struct {
	*UtilityVM
}

// Compile-time check to make sure KryptonContainer implements
// the cow.Container interface.
var _ cow.Container = &KryptonContainer{}

// Shutdown sends a shutdown request to the container (but does not wait for
// the shutdown to complete).
func (container *KryptonContainer) Shutdown(ctx context.Context) error {
	// TODO(pbozzay): This currently fails with "Invalid JSON" so we are using Terminate().
	// return container.hcsSystem.Shutdown(ctx)
	return container.hcsSystem.Terminate(ctx)
}

// Modify sends a modify request to the container.
func (container *KryptonContainer) Modify(ctx context.Context, config interface{}) (err error) {
	return errors.New("Modify API is not implemented for Krypton")
}

// Properties returns the requested container properties targeting a V1 schema container.
func (container *KryptonContainer) Properties(ctx context.Context, types ...schema1.PropertyType) (_ *schema1.ContainerProperties, err error) {
	return nil, errors.New("Properties API is not implemented for Krypton")
}

// PropertiesV2 returns the requested container properties targeting a V2 schema container.
func (container *KryptonContainer) PropertiesV2(ctx context.Context, types ...hcsschema.PropertyType) (_ *hcsschema.Properties, err error) {
	return nil, errors.New("PropertiesV2 API is not implemented for Krypton")
}
