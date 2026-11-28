package remotebridge

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agbox/internal/config"
	"agbox/internal/mounttab"
	"agbox/internal/remoteproto"
)

const (
	statusQueryMaxBytes = 4 * 1024
	statusQueryTimeout  = 2 * time.Second
	daemonStartTimeout  = 5 * time.Second
)

func (b *Bridge) startControlSocket() error {
	sockDir := filepath.Dir(b.opts.SockPath)
	if err := config.EnsurePrivateDir(sockDir); err != nil {
		return fmt.Errorf("prepare remote socket dir: %w", err)
	}
	if info, err := os.Lstat(b.opts.SockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing non-socket path at %s", b.opts.SockPath)
		}
		_ = os.Remove(b.opts.SockPath)
	}
	addr, err := net.ResolveUnixAddr("unix", b.opts.SockPath)
	if err != nil {
		return fmt.Errorf("resolve remote socket %s: %w", b.opts.SockPath, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", b.opts.SockPath, err)
	}
	if err := os.Chmod(b.opts.SockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(b.opts.SockPath)
		return fmt.Errorf("chmod %s: %w", b.opts.SockPath, err)
	}
	b.listener = ln

	b.wg.Add(1)
	go b.acceptControlLoop(ln)
	return nil
}

func (b *Bridge) closeControlSocket() {
	if b.listener != nil {
		_ = b.listener.Close()
	}
	b.mu.Lock()
	sess := b.broker
	b.broker = nil
	b.denyAllPendingLocked()
	b.mu.Unlock()
	if sess != nil {
		sess.close()
	}
	if b.opts.SockPath != "" {
		if info, err := os.Lstat(b.opts.SockPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(b.opts.SockPath)
		}
	}
}

func (b *Bridge) acceptControlLoop(ln *net.UnixListener) {
	defer b.wg.Done()
	wantUID := os.Geteuid()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			select {
			case <-b.stopCh:
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
		}
		b.wg.Add(1)
		go func(c *net.UnixConn) {
			defer b.wg.Done()
			b.handleControlConn(c, wantUID)
		}(conn)
	}
}

func (b *Bridge) handleControlConn(conn *net.UnixConn, wantUID int) {
	defer conn.Close()
	if err := VerifyUnixSocketOwner("", conn, wantUID); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(statusQueryTimeout))
	typ, payload, _, err := remoteproto.ReadFrame(conn, statusQueryMaxBytes)
	if err != nil || typ != "bridge" {
		return
	}
	var msg remoteproto.BridgeMessage
	if err := remoteproto.DecodeStrict(payload, &msg); err != nil {
		return
	}

	switch msg.Op {
	case "status":
		st := b.Status()
		_ = conn.SetWriteDeadline(time.Now().Add(statusQueryTimeout))
		_, _ = remoteproto.WriteFrame(conn, "status", st, statusQueryMaxBytes)
		return

	case "attach":
		_ = conn.SetReadDeadline(time.Time{})
		sess := &brokerSession{
			conn:     conn,
			peer:     msg.Peer,
			remoteID: msg.RemoteID,
			policy:   msg.Policy,
			sendCh:   make(chan remoteproto.BridgeMessage, brokerSendQueueCap),
			closed:   make(chan struct{}),
		}
		b.mu.Lock()
		if b.broker != nil {
			b.mu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(statusQueryTimeout))
			_, _ = remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
				Op:    "attach_err",
				Error: "another remote broker is already attached to this sandbox",
			}, remoteproto.PostAuthMaxFrameBytes)
			return
		}
		b.broker = sess
		sess.sendCh <- remoteproto.BridgeMessage{Op: "attach_ok"}
		b.wg.Add(1)
		go b.brokerWriterLoop(sess)
		b.mu.Unlock()

		b.serveBrokerStream(sess)
		b.detachBroker(sess)
	}
}

func (b *Bridge) brokerWriterLoop(sess *brokerSession) {
	defer b.wg.Done()
	for {
		select {
		case <-sess.closed:
			return
		case <-b.stopCh:
			sess.close()
			return
		case msg := <-sess.sendCh:
			_ = sess.conn.SetWriteDeadline(time.Now().Add(brokerWriteDeadline))
			if _, err := remoteproto.WriteFrame(sess.conn, "bridge", msg, remoteproto.PostAuthMaxFrameBytes); err != nil {
				b.detachBroker(sess)
				return
			}
		}
	}
}

func (b *Bridge) serveBrokerStream(sess *brokerSession) {
	for {
		typ, payload, _, err := remoteproto.ReadFrame(sess.conn, remoteproto.PostAuthMaxFrameBytes)
		if err != nil {
			return
		}
		if typ != "bridge" {
			return
		}
		var msg remoteproto.BridgeMessage
		if err := remoteproto.DecodeStrict(payload, &msg); err != nil {
			return
		}
		switch msg.Op {
		case "resp":
			if msg.SlotID != "" && msg.Response != nil {
				b.CompleteSlot(msg.SlotID, *msg.Response)
			}
		case "update_status":
			b.mu.Lock()
			if b.broker == sess {
				if msg.Peer != "" {
					sess.peer = msg.Peer
				}
				if msg.RemoteID != "" {
					sess.remoteID = msg.RemoteID
				}
				sess.policy = msg.Policy
			}
			b.mu.Unlock()
		}
	}
}

func (b *Bridge) detachBroker(sess *brokerSession) {
	sess.close()
	b.mu.Lock()
	if b.broker == sess {
		b.broker = nil
		b.denyAllPendingLocked()
	}
	b.mu.Unlock()
}

// Status returns the live attachment and pending-slot state of the bridge.
func (b *Bridge) Status() remoteproto.BridgeStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	pending := 0
	for _, sl := range b.slots {
		if sl.state == slotPending && !sl.revoked {
			pending++
		}
	}
	st := remoteproto.BridgeStatus{Pending: pending}
	if b.broker != nil {
		st.Attached = true
		st.Peer = b.broker.peer
		st.RemoteID = b.broker.remoteID
		st.Policy = b.broker.policy
	}
	return st
}

// QueryStatus queries remote.sock with mutual SO_PEERCRED and returns BridgeStatus.
func QueryStatus(sockPath string) (remoteproto.BridgeStatus, error) {
	if err := VerifyUnixSocketOwner(sockPath, nil, os.Geteuid()); err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	defer conn.Close()
	if err := VerifyUnixSocketOwner("", conn, os.Geteuid()); err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(statusQueryTimeout))
	if _, err := remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{Op: "status"}, statusQueryMaxBytes); err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	typ, payload, _, err := remoteproto.ReadFrame(conn, statusQueryMaxBytes)
	if err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	if typ != "status" {
		return remoteproto.BridgeStatus{}, fmt.Errorf("unexpected bridge status frame %q", typ)
	}
	var st remoteproto.BridgeStatus
	if err := remoteproto.DecodeStrict(payload, &st); err != nil {
		return remoteproto.BridgeStatus{}, err
	}
	return st, nil
}

// DialAttach connects exclusively to remote.sock as the active host broker.
func DialAttach(sockPath, peer, remoteID, policy string) (*net.UnixConn, error) {
	if err := VerifyUnixSocketOwner(sockPath, nil, os.Geteuid()); err != nil {
		return nil, err
	}
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}
	if err := VerifyUnixSocketOwner("", conn, os.Geteuid()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(statusQueryTimeout))
	if _, err := remoteproto.WriteFrame(conn, "bridge", remoteproto.BridgeMessage{
		Op:       "attach",
		Peer:     peer,
		RemoteID: remoteID,
		Policy:   policy,
	}, statusQueryMaxBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	typ, payload, _, err := remoteproto.ReadFrame(conn, statusQueryMaxBytes)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if typ != "bridge" {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected bridge attach reply %q", typ)
	}
	var reply remoteproto.BridgeMessage
	if err := remoteproto.DecodeStrict(payload, &reply); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply.Op == "attach_err" {
		_ = conn.Close()
		return nil, errors.New(reply.Error)
	}
	if reply.Op != "attach_ok" {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected bridge attach status %q", reply.Op)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// StartSubprocess starts `agbox __filter -bridge -mnt <mntDir> -sock <sockPath>` in the background.
// The parent writes pidFile and waits for both the mountpoint and remote.sock to become ready.
func StartSubprocess(exePath, mntDir, sockPath, pidFile string, dieWithParent bool) (int, error) {
	if exePath == "" || mntDir == "" || sockPath == "" || pidFile == "" {
		return 0, errors.New("bridge subprocess requires exePath, mntDir, sockPath, and pidFile")
	}
	if err := config.EnsurePrivateDir(mntDir); err != nil {
		return 0, err
	}
	errLogPath := strings.TrimSuffix(pidFile, ".pid") + ".err"
	errFile, err := os.OpenFile(errLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open bridge error log %s: %w", errLogPath, err)
	}

	args := []string{
		"__filter",
		"-bridge",
		"-mnt", mntDir,
		"-sock", sockPath,
	}
	cmd := exec.Command(exePath, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = errFile
	sysAttr := &syscall.SysProcAttr{}
	if dieWithParent {
		sysAttr.Pdeathsig = syscall.SIGTERM
	} else {
		sysAttr.Setsid = true
	}
	cmd.SysProcAttr = sysAttr

	if err := cmd.Start(); err != nil {
		_ = errFile.Close()
		return 0, fmt.Errorf("start remote bridge daemon: %w", err)
	}
	_ = errFile.Close()

	pid := cmd.Process.Pid
	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()

	cleanupFailedStart := func(alreadyExited bool) {
		if !alreadyExited {
			_ = syscall.Kill(pid, syscall.SIGTERM)
			select {
			case <-exitCh:
			case <-time.After(500 * time.Millisecond):
				_ = syscall.Kill(pid, syscall.SIGKILL)
				select {
				case <-exitCh:
				case <-time.After(500 * time.Millisecond):
				}
			}
		}
		_ = os.Remove(pidFile)
		_ = os.Remove(sockPath)
		if mounted, _ := mounttab.IsPathMounted(mntDir); mounted {
			ctl := mounttab.OSController{}
			if ctl.Unmount(mntDir, false) != nil {
				_ = ctl.Unmount(mntDir, true)
			}
		}
	}

	if err := writePrivateFileNoFollow(pidFile, []byte(strconv.Itoa(pid)+"\n")); err != nil {
		cleanupFailedStart(false)
		return 0, fmt.Errorf("write bridge pid file %s: %w", pidFile, err)
	}

	deadline := time.Now().Add(daemonStartTimeout)
	for time.Now().Before(deadline) {
		select {
		case wErr := <-exitCh:
			detail := readTailFile(errLogPath)
			cleanupFailedStart(true)
			if detail != "" {
				return 0, fmt.Errorf("remote bridge exited early: %s", detail)
			}
			return 0, fmt.Errorf("remote bridge exited early: %v", wErr)
		default:
		}
		mounted, _ := mounttab.IsPathMounted(mntDir)
		if mounted {
			if _, sErr := QueryStatus(sockPath); sErr == nil {
				return pid, nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	cleanupFailedStart(false)
	detail := readTailFile(errLogPath)
	if detail != "" {
		return 0, fmt.Errorf("remote bridge did not become ready at %s (%s)", mntDir, detail)
	}
	return 0, fmt.Errorf("remote bridge did not become ready at %s", mntDir)
}

func writePrivateFileNoFollow(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	cErr := f.Close()
	if wErr != nil {
		return wErr
	}
	return cErr
}

func readTailFile(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// RunMain runs the background FUSE bridge process for `agbox __filter -bridge ...`.
func RunMain(args []string) int {
	fsFlags := flag.NewFlagSet("agbox __filter -bridge", flag.ContinueOnError)
	bridgeMode := fsFlags.Bool("bridge", false, "run remote command FUSE bridge")
	mntDir := fsFlags.String("mnt", "", "FUSE mount directory")
	sockPath := fsFlags.String("sock", "", "Unix control socket path")
	guestUID := fsFlags.Uint("guest-uid", config.GuestUID, "mapped guest UID")
	guestGID := fsFlags.Uint("guest-gid", config.GuestGID, "mapped guest GID")
	if err := fsFlags.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "parse bridge flags: %v\n", err)
		return 2
	}
	if !*bridgeMode || *mntDir == "" || *sockPath == "" {
		fmt.Fprintln(os.Stderr, "usage: agbox __filter -bridge -mnt <dir> -sock <path>")
		return 2
	}

	b, err := New(Options{
		MountDir:         *mntDir,
		SockPath:         *sockPath,
		GuestUID:         uint32(*guestUID),
		GuestGID:         uint32(*guestGID),
		RequireStaticELF: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if err := b.Mount(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigCh
		_ = b.Close()
	}()

	b.Wait()
	_ = b.Close()
	return 0
}
