package main

import (
	"context"
	"sync"

	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oci"
	"github.com/Microsoft/hcsshim/osversion"
	"github.com/Microsoft/hcsshim/pkg/annotations"
	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/task"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// Creates and returns a kryptonPod. This is a dummy pod with the sole purpose of
// doing basic bookkeeping for its pool of tasks, and exposing an interface to
// create or destroy workload containers.
func createKryptonPod(ctx context.Context, events publisher, req *task.CreateTaskRequest, s *specs.Spec) (shimPod, error) {
	if osversion.Get().Build < osversion.V20H1 {
		return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "Krypton pod support is not available on Windows versions previous to 20H1(%d)", osversion.RS5)
	}

	p := kryptonPod{
		events: events,
		id:     req.ID,
	}

	// Create a dummy sandbox task. This is used to signal that the sandbox process
	// is alive and well.
	// Settings nsid as "" due to having a nil parent
	p.sandboxTask = newWcowPodSandboxTask(ctx, events, req.ID, req.Bundle, nil, "")

	// Publish the created event. We only do this for a fake WCOW task. A
	// HCS Task will event itself based on actual process lifetime.
	events.publishEvent(
		ctx,
		runtime.TaskCreateEventTopic,
		&eventstypes.TaskCreate{
			ContainerID: req.ID,
			Bundle:      req.Bundle,
			Rootfs:      req.Rootfs,
			IO: &eventstypes.TaskIO{
				Stdin:    req.Stdin,
				Stdout:   req.Stdout,
				Stderr:   req.Stderr,
				Terminal: req.Terminal,
			},
			Checkpoint: "",
			Pid:        0,
		})

	return &p, nil
}

var _ = (shimPod)(&pod{})

type kryptonPod struct {
	events publisher
	// id is the id of the sandbox task when the pod is created.
	//
	// It MUST be treated as read only in the lifetime of the pod.
	id string
	// sandboxTask is the task that represents the sandbox.
	//
	// Note: The invariant `id==sandboxTask.ID()` MUST be true.
	//
	// It MUST be treated as read only in the lifetime of the pod.
	sandboxTask shimTask
	// wcl is the workload create mutex. All calls to CreateTask must hold this
	// lock while the ID reservation takes place. Once the ID is held it is safe
	// to release the lock to allow concurrent creates.
	wcl           sync.Mutex
	workloadTasks sync.Map
}

func (p *kryptonPod) ID() string {
	return p.id
}

func (p *kryptonPod) CreateTask(ctx context.Context, req *task.CreateTaskRequest, s *specs.Spec) (_ shimTask, err error) {
	if req.ID == p.id {
		return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "task with id: '%s' already exists", req.ID)
	}
	e, _ := p.sandboxTask.GetExec("")
	if e.State() != shimExecStateRunning {
		return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "task with id: '%s' cannot be created in kryptonPod: '%s' which is not running", req.ID, p.id)
	}

	p.wcl.Lock()
	_, loaded := p.workloadTasks.LoadOrStore(req.ID, nil)
	if loaded {
		return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "task with id: '%s' already exists id kryptonPod: '%s'", req.ID, p.id)
	}
	p.wcl.Unlock()
	defer func() {
		if err != nil {
			p.workloadTasks.Delete(req.ID)
		}
	}()

	ct, sid, err := oci.GetSandboxTypeAndID(s.Annotations)
	if err != nil {
		return nil, err
	}
	if ct != oci.KubernetesContainerTypeContainer {
		return nil, errors.Wrapf(
			errdefs.ErrFailedPrecondition,
			"expected annotation: '%s': '%s' got '%s'",
			annotations.KubernetesContainerType,
			oci.KubernetesContainerTypeContainer,
			ct)
	}
	if sid != p.id {
		return nil, errors.Wrapf(
			errdefs.ErrFailedPrecondition,
			"expected annotation '%s': '%s' got '%s'",
			annotations.KubernetesSandboxID,
			p.id,
			sid)
	}

	st, err := newKryptonTask(ctx, p.events, req, s)
	if err != nil {
		return nil, err
	}

	p.workloadTasks.Store(req.ID, st)

	return st, nil
}

func (p *kryptonPod) GetTask(tid string) (shimTask, error) {
	if tid == p.id {
		return p.sandboxTask, nil
	}
	raw, loaded := p.workloadTasks.Load(tid)
	if !loaded {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "task with id: '%s' not found", tid)
	}
	return raw.(shimTask), nil
}

func (p *kryptonPod) KillTask(ctx context.Context, tid, eid string, signal uint32, all bool) error {
	log.G(ctx).WithField("id", p.id).Debug("Killing requested task.")

	t, err := p.GetTask(tid)
	if err != nil {
		return err
	}
	if all && eid != "" {
		return errors.Wrapf(errdefs.ErrFailedPrecondition, "cannot signal all with non empty ExecID: '%s'", eid)
	}
	eg := errgroup.Group{}
	if all && tid == p.id {
		// We are in a kill all on the sandbox task. Signal everything.
		p.workloadTasks.Range(func(key, value interface{}) bool {
			wt := value.(shimTask)
			eg.Go(func() error {
				return wt.KillExec(ctx, eid, signal, all)
			})

			// iterate all
			return false
		})
	}
	eg.Go(func() error {
		return t.KillExec(ctx, eid, signal, all)
	})

	log.G(ctx).WithField("id", p.id).Debug("Waiting on kill task request.")
	return eg.Wait()
}

func (p *kryptonPod) DeleteTask(ctx context.Context, tid string) error {
	// Deleting the sandbox task is a no-op, since the service should delete its
	// reference to the sandbox task or pod, and `p.sandboxTask != nil` is an
	// invariant that is relied on elsewhere.
	// However, still get the init exec for all tasks to ensure that they have
	// been properly stopped.

	t, err := p.GetTask(tid)
	if err != nil {
		return errors.Wrap(err, "could not find task to delete")
	}

	e, err := t.GetExec("")
	if err != nil {
		return errors.Wrap(err, "could not get initial exec")
	}
	if e.State() == shimExecStateRunning {
		return errors.Wrap(errdefs.ErrFailedPrecondition, "cannot delete task with running exec")
	}

	if p.id != tid {
		p.workloadTasks.Delete(tid)
	}

	return nil
}
