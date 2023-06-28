package main

import (
	"context"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim/internal/cmd"
	"github.com/Microsoft/hcsshim/internal/cow"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/internal/signals"
	"github.com/Microsoft/hcsshim/internal/uvm"
	"github.com/Microsoft/hcsshim/osversion"
	eventstypes "github.com/containerd/containerd/api/events"
	containerd_v1_types "github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

// newKryptonExec creates an exec to track the lifetime of `spec` in `c` which is
// actually created on the call to `Start()`. If `id==tid` then this is the init
// exec and the exec will also start `c` on the call to `Start()` before execing
// the process `spec.Process`.
func newKryptonExec(
	ctx context.Context,
	events publisher,
	tid string,
	c cow.Container,
	id, bundle string,
	spec *specs.Process,
	s *specs.Spec,
	uvm *uvm.UtilityVM,
	io cmd.UpstreamIO) shimExec {
	log.G(ctx).WithFields(logrus.Fields{
		"tid":    tid,
		"eid":    id, // Init exec ID is always same as Task ID
		"bundle": bundle,
	}).Debug("newKryptonExec")

	ke := &kryptonExec{
		events:      events,
		tid:         tid,
		c:           c,
		id:          id,
		bundle:      bundle,
		spec:        spec,
		s:           s,
		uvm:         uvm,
		io:          io,
		processDone: make(chan struct{}),
		state:       shimExecStateCreated,
		exitStatus:  255, // By design for non-exited process status.
		exited:      make(chan struct{}),
	}
	go ke.waitForContainerExit()
	return ke
}

var _ = (shimExec)(&kryptonExec{})

type kryptonExec struct {
	events publisher
	// tid is the task id of the container hosting this process.
	//
	// This MUST be treated as read only in the lifetime of the exec.
	tid string
	// c is the hosting container for this exec.
	//
	// This MUST be treated as read only in the lifetime of the exec.
	c cow.Container
	// id is the id of this process.
	//
	// This MUST be treated as read only in the lifetime of the exec.
	id string
	// bundle is the on disk path to the folder containing the `process.json`
	// describing this process. If `id==tid` the process is described in the
	// `config.json`.
	//
	// This MUST be treated as read only in the lifetime of the exec.
	bundle string
	// spec is the OCI Process spec that was passed in at create time. This is
	// stored because we don't actually create the process until the call to
	// `Start`.
	//
	// This MUST be treated as read only in the lifetime of the exec.
	spec *specs.Process
	s    *specs.Spec
	uvm  *uvm.UtilityVM
	// io is the upstream io connections used for copying between the upstream
	// io and the downstream io. The upstream IO MUST already be connected at
	// create time in order to be valid.
	//
	// This MUST be treated as read only in the lifetime of the exec.
	io              cmd.UpstreamIO
	processDone     chan struct{}
	processDoneOnce sync.Once

	// sl is the state lock that MUST be held to safely read/write any of the
	// following members.
	sl         sync.Mutex
	state      shimExecState
	pid        int
	exitStatus uint32
	exitedAt   time.Time
	p          *cmd.Cmd

	// exited is a wait block which waits async for the process to exit.
	exited     chan struct{}
	exitedOnce sync.Once
}

func (ke *kryptonExec) ID() string {
	return ke.id
}

func (ke *kryptonExec) Pid() int {
	ke.sl.Lock()
	defer ke.sl.Unlock()
	return ke.pid
}

func (ke *kryptonExec) State() shimExecState {
	ke.sl.Lock()
	defer ke.sl.Unlock()
	return ke.state
}

func (ke *kryptonExec) Status() *task.StateResponse {
	ke.sl.Lock()
	defer ke.sl.Unlock()

	var s containerd_v1_types.Status
	switch ke.state {
	case shimExecStateCreated:
		s = containerd_v1_types.StatusCreated
	case shimExecStateRunning:
		s = containerd_v1_types.StatusRunning
	case shimExecStateExited:
		s = containerd_v1_types.StatusStopped
	}

	return &task.StateResponse{
		ID:         ke.tid,
		ExecID:     ke.id,
		Bundle:     ke.bundle,
		Pid:        uint32(ke.pid),
		Status:     s,
		Stdin:      ke.io.StdinPath(),
		Stdout:     ke.io.StdoutPath(),
		Stderr:     ke.io.StderrPath(),
		Terminal:   ke.io.Terminal(),
		ExitStatus: ke.exitStatus,
		ExitedAt:   ke.exitedAt,
	}
}

func (ke *kryptonExec) startInternal(ctx context.Context, initializeContainer bool) (err error) {
	ke.sl.Lock()
	defer ke.sl.Unlock()

	if ke.state != shimExecStateCreated {
		return newExecInvalidStateError(ke.tid, ke.id, ke.state, "start")
	}

	defer func() {
		if err != nil {
			ke.exitFromCreatedL(ctx, 1)
		}
	}()

	// The container may need to be started
	if initializeContainer {
		err = ke.c.Start(ctx)
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				ke.c.Terminate(ctx)
				ke.c.Close()
			}
		}()
	}

	nsid := ""
	if ke.s.Windows != nil && ke.s.Windows.Network != nil {
		nsid = ke.s.Windows.Network.NetworkNamespace
	}

	if nsid != "" {
		log.G(ctx).Debugf("Network namespace : %s", nsid)
		if err := ke.uvm.ConfigureNetworking(ctx, nsid); err != nil {
			return errors.Wrapf(err, "failed to setup networking for pod")
		}
	}

	// Set up any requested folder mounts. This is done after the container is
	// started because GCS must set up BindFlt mappings in the guest. However it must
	// be completed before the init process is started so that dependent workloads do
	// not race with folder mount.
	for _, m := range ke.s.Mounts {

		// Mount options are fstab-formatted. Search the list for read only tags.
		readOnly := false
		for _, m := range m.Options {
			if m == "ro" {
				readOnly = true
				break
			}
		}

		// Add the mount.
		err = ke.uvm.Share(ctx, m.Source, m.Destination, readOnly)
		if err != nil {
			return err
		}
	}

	command := cmd.CommandContext(ctx, ke.c, ke.spec.Args[0], ke.spec.Args[1:]...)
	command.Spec.User.Username = `NT AUTHORITY\SYSTEM`
	command.Spec.Terminal = ke.spec.Terminal
	command.Stdin = ke.io.Stdin()
	command.Stdout = ke.io.Stdout()
	command.Stderr = ke.io.Stderr()
	command.Log = log.G(ctx).WithFields(logrus.Fields{
		"tid": ke.tid,
		"eid": ke.id,
	})

	err = command.Start()
	if err != nil {
		return err
	}
	ke.p = command

	// Assign tke PID and transition the state.
	ke.pid = ke.p.Process.Pid()
	ke.state = shimExecStateRunning

	// Publish tke task/exec start event. This MUST happen before waitForExit to
	// avoid publishing the exit previous to the start.
	if ke.id != ke.tid {
		ke.events.publishEvent(
			ctx,
			runtime.TaskExecStartedEventTopic,
			&eventstypes.TaskExecStarted{
				ContainerID: ke.tid,
				ExecID:      ke.id,
				Pid:         uint32(ke.pid),
			})
	} else {
		ke.events.publishEvent(
			ctx,
			runtime.TaskStartEventTopic,
			&eventstypes.TaskStart{
				ContainerID: ke.tid,
				Pid:         uint32(ke.pid),
			})
	}

	// wait in the background for the exit.
	go ke.waitForExit()
	return nil
}

func (ke *kryptonExec) Start(ctx context.Context) (err error) {
	// If ke.id == ke.tid then this is the init exec.
	// We need to initialize the container itself before starting this exec.
	return ke.startInternal(ctx, ke.id == ke.tid)
}

func (ke *kryptonExec) Kill(ctx context.Context, signal uint32) error {
	ke.sl.Lock()
	defer ke.sl.Unlock()
	switch ke.state {
	case shimExecStateCreated:
		ke.exitFromCreatedL(ctx, 1)
		return nil
	case shimExecStateRunning:
		supported := false
		if osversion.Get().Build >= osversion.RS5 {
			// TODO(pbozzay): Change this
			//supported = ke.host == nil || ke.host.SignalProcessSupported()
			supported = false
		}
		var options interface{}
		var err error
		var opt *guestresource.SignalProcessOptionsWCOW
		opt, err = signals.ValidateWCOW(int(signal), supported)
		if opt != nil {
			options = opt
		}
		if err != nil {
			return errors.Wrapf(errdefs.ErrFailedPrecondition, "signal %d: %v", signal, err)
		}
		var delivered bool
		if supported && options != nil {
			delivered, err = ke.p.Process.Signal(ctx, options)
		} else {
			// legacy path before signals support OR if WCOW with signals
			// support needs to issue a terminate.
			delivered, err = ke.p.Process.Kill(ctx)
		}
		if err != nil {
			return err
		}
		if !delivered {
			return errors.Wrapf(errdefs.ErrNotFound, "exec: '%s' in task: '%s' not found", ke.id, ke.tid)
		}
		return nil
	case shimExecStateExited:
		return errors.Wrapf(errdefs.ErrNotFound, "exec: '%s' in task: '%s' not found", ke.id, ke.tid)
	default:
		return newExecInvalidStateError(ke.tid, ke.id, ke.state, "kill")
	}
}

func (ke *kryptonExec) ResizePty(ctx context.Context, width, height uint32) error {
	ke.sl.Lock()
	defer ke.sl.Unlock()
	if !ke.io.Terminal() {
		return errors.Wrapf(errdefs.ErrFailedPrecondition, "exec: '%s' in task: '%s' is not a tty", ke.id, ke.tid)
	}

	if ke.state == shimExecStateRunning {
		return ke.p.Process.ResizeConsole(ctx, uint16(width), uint16(height))
	}
	return nil
}

func (ke *kryptonExec) CloseIO(ctx context.Context, stdin bool) error {
	// If we have any upstream IO we close the upstream connection. This will
	// unblock the `io.Copy` in the `Start()` call which will signal
	// `ke.p.CloseStdin()`. If `ke.io.Stdin()` is already closed this is safe to
	// call multiple times.
	ke.io.CloseStdin(ctx)
	return nil
}

func (ke *kryptonExec) Wait() *task.StateResponse {
	<-ke.exited
	return ke.Status()
}

func (ke *kryptonExec) ForceExit(ctx context.Context, status int) {
	ke.sl.Lock()
	defer ke.sl.Unlock()
	if ke.state != shimExecStateExited {
		switch ke.state {
		case shimExecStateCreated:
			ke.exitFromCreatedL(ctx, status)
		case shimExecStateRunning:
			// Kill the process to unblock `ke.waitForExit`
			ke.p.Process.Kill(ctx)
		}
	}
}

// exitFromCreatedL transitions the shim to the exited state from the created
// state. It is the callers responsibility to hold `ke.sl` for the durration of
// this transition.
//
// This call is idempotent and will not affect any state if the shim is already
// in the `shimExecStateExited` state.
//
// To transition for a created state the following must be done:
//
// 1. Issue `ke.processDoneCancel` to unblock the goroutine
// `ke.waitForContainerExit()“.
//
// 2. Set `ke.state`, `ke.exitStatus` and `ke.exitedAt` to the exited values.
//
// 3. Release any upstream IO resources that were never used in a copy.
//
// 4. Close `ke.exited` channel to unblock any waiters who might have called
// `Create`/`Wait`/`Start` which is a valid pattern.
//
// We DO NOT send the async `TaskExit` event because we never would have sent
// the `TaskStart`/`TaskExecStarted` event.
func (ke *kryptonExec) exitFromCreatedL(ctx context.Context, status int) {
	if ke.state != shimExecStateExited {
		// Avoid logging the force if we already exited gracefully
		log.G(ctx).WithField("status", status).Debug("kryptonExec::exitFromCreatedL")

		// Unblock the container exit goroutine
		ke.processDoneOnce.Do(func() { close(ke.processDone) })
		// Transition this exec
		ke.state = shimExecStateExited
		ke.exitStatus = uint32(status)
		ke.exitedAt = time.Now()
		// Release all upstream IO connections (if any)
		ke.io.Close(ctx)
		// Free any waiters
		ke.exitedOnce.Do(func() {
			close(ke.exited)
		})
	}
}

// waitForExit waits for the `ke.p` to exit. This MUST only be called after a
// successful call to `Create` and MUST not be called more than once.
//
// This MUST be called via a goroutine.
//
// In the case of an exit from a running process the following must be done:
//
// 1. Wait for `ke.p` to exit.
//
// 2. Issue `ke.processDoneCancel` to unblock the goroutine
// `ke.waitForContainerExit()` (if still running). We do this early to avoid the
// container exit also attempting to kill the process. However this race
// condition is safe and handled.
//
// 3. Capture the process exit code and set `ke.state`, `ke.exitStatus` and
// `ke.exitedAt` to the exited values.
//
// 4. Wait for all IO to complete and release any upstream IO connections.
//
// 5. Send the async `TaskExit` to upstream listeners of any events.
//
// 6. Close `ke.exited` channel to unblock any waiters who might have called
// `Create`/`Wait`/`Start` which is a valid pattern.
//
// 7. Finally, save the UVM and this container as a template if specified.
func (ke *kryptonExec) waitForExit() {
	ctx, span := trace.StartSpan(context.Background(), "kryptonExec::waitForExit")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("tid", ke.tid),
		trace.StringAttribute("eid", ke.id))

	err := ke.p.Process.Wait()
	if err != nil {
		log.G(ctx).WithError(err).Error("failed process Wait")
	}

	// Issue the process cancellation to unblock the container wait as early as
	// possible.
	ke.processDoneOnce.Do(func() { close(ke.processDone) })

	code, err := ke.p.Process.ExitCode()
	if err != nil {
		log.G(ctx).WithError(err).Error("failed to get ExitCode")
	} else {
		log.G(ctx).WithField("exitCode", code).Debug("exited")
	}

	ke.sl.Lock()
	ke.state = shimExecStateExited
	ke.exitStatus = uint32(code)
	ke.exitedAt = time.Now()
	ke.sl.Unlock()

	// Wait for all IO copies to complete and free the resources.
	ke.p.Wait()
	ke.io.Close(ctx)

	// Only send the `runtime.TaskExitEventTopic` notification if this is a true
	// exec. For the `init` exec this is handled in task teardown.
	if ke.tid != ke.id {
		// We had a valid process so send the exited notification.
		ke.events.publishEvent(
			ctx,
			runtime.TaskExitEventTopic,
			&eventstypes.TaskExit{
				ContainerID: ke.tid,
				ID:          ke.id,
				Pid:         uint32(ke.pid),
				ExitStatus:  ke.exitStatus,
				ExitedAt:    ke.exitedAt,
			})
	}

	// Free any waiters.
	ke.exitedOnce.Do(func() {
		close(ke.exited)
	})
}

// waitForContainerExit waits for `ke.c` to exit. Depending on the exec's state
// will forcibly transition this exec to the exited state and unblock any
// waiters.
//
// This MUST be called via a goroutine at exec create.
func (ke *kryptonExec) waitForContainerExit() {
	ctx, span := trace.StartSpan(context.Background(), "kryptonExec::waitForContainerExit")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("tid", ke.tid),
		trace.StringAttribute("eid", ke.id))

	cexit := make(chan struct{})
	go func() {
		ke.c.Wait()
		close(cexit)
	}()
	select {
	case <-cexit:
		// Container exited first. We need to force the process into the exited
		// state and cleanup any resources
		ke.sl.Lock()
		switch ke.state {
		case shimExecStateCreated:
			ke.exitFromCreatedL(ctx, 1)
		case shimExecStateRunning:
			// Kill the process to unblock `ke.waitForExit`.
			ke.p.Process.Kill(ctx)
		}
		ke.sl.Unlock()
	case <-ke.processDone:
		// Process exited first. This is the normal case do nothing because
		// `ke.waitForExit` will release any waiters.
	}
}
