package main

import (
	"bytes"
	"database/sql"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	_ "github.com/mattn/go-sqlite3"
)

// Embed the pre-compiled BPF object directly into the binary.
// No bpf2go, no generated files — just the raw .o bytes.
//
//go:embed bpf/tracker.bpf.o
var bpfObject []byte

// ─── Event constants (must match tracker.bpf.c) ───────────────────────────────

const (
	EventExec = uint32(1)
	EventOpen = uint32(2)
)

// ─── Event struct (must match C memory layout exactly) ────────────────────────
// __u32 event_type  → 4 bytes
// __u32 pid         → 4 bytes
// __u32 tgid        → 4 bytes
// __u32 ppid        → 4 bytes
// __u32 uid         → 4 bytes
// char  comm[16]    → 16 bytes
// char  filename[256] → 256 bytes
// Total: 292 bytes

type bpfEvent struct {
	EventType uint32
	Pid       uint32
	Tgid      uint32
	Ppid      uint32
	Uid       uint32
	Comm      [16]byte
	Filename  [256]byte
}

// ─── Sensitive files ──────────────────────────────────────────────────────────

var sensitiveFiles = map[string]string{
	"/etc/shadow":                "credential-store",
	"/etc/passwd":                "credential-store",
	"/etc/gshadow":               "credential-store",
	"/etc/group":                 "credential-store",
	"/etc/ssh/sshd_config":       "ssh-config",
	"/etc/ssh/ssh_config":        "ssh-config",
	"/root/.ssh/authorized_keys": "ssh-persistence",
	"/root/.ssh/id_rsa":          "ssh-private-key",
	"/root/.ssh/id_ed25519":      "ssh-private-key",
	"/etc/ssh/ssh_host_rsa_key":  "ssh-host-key",
	"/etc/pam.d/sshd":            "pam-config",
	"/etc/pam.d/su":              "pam-config",
	"/etc/pam.d/sudo":            "pam-config",
	"/etc/nsswitch.conf":         "nss-config",
	"/etc/ld.so.preload":         "ld-preload-hijack",
	"/etc/sudoers":               "priv-escalation",
	"/etc/sudoers.d/":            "priv-escalation",
	"/etc/crontab":               "cron-persistence",
	"/etc/cron.d/":               "cron-persistence",
	"/etc/rc.local":              "init-persistence",
	"/etc/systemd/system/":       "systemd-persistence",
	"/lib/systemd/system/":       "systemd-persistence",
	"/etc/ld.so.conf":            "linker-config",
	"/etc/hosts":                 "dns-spoofing",
	"/etc/resolv.conf":           "dns-config",
	"/etc/modules":               "kernel-modules",
	"/etc/modprobe.d/":           "kernel-modules",
	"/etc/audit/auditd.conf":     "audit-config",
	"/var/log/auth.log":          "auth-log",
	"/var/log/secure":            "auth-log",
	"/etc/ssl/private/":          "private-keys",
}

func isSensitive(filename string) (string, bool) {
	if cat, ok := sensitiveFiles[filename]; ok {
		return cat, true
	}
	for prefix, cat := range sensitiveFiles {
		if strings.HasSuffix(prefix, "/") && strings.HasPrefix(filename, prefix) {
			return cat, true
		}
	}
	return "", false
}

// ─── SQLite ───────────────────────────────────────────────────────────────────

const schema = `
CREATE TABLE IF NOT EXISTS processes (
    pid      INTEGER PRIMARY KEY,
    ppid     INTEGER NOT NULL,
    uid      INTEGER NOT NULL,
    comm     TEXT    NOT NULL,
    cmdline  TEXT    NOT NULL DEFAULT '',
    username TEXT    NOT NULL DEFAULT '',
    seen_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ppid ON processes(ppid);
`

func setupDB() (*sql.DB, error) {
	if err := os.MkdirAll("/var/lib/filewatch", 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", "/var/lib/filewatch/processes.db?_journal=WAL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(schema)
	return db, err
}

func upsertProcess(db *sql.DB, pid, ppid, uid uint32, comm string) {
	cmdline := readCmdline(pid)
	username := resolveUID(uid)
	_, err := db.Exec(`
        INSERT INTO processes (pid, ppid, uid, comm, cmdline, username, seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(pid) DO UPDATE SET
            ppid=excluded.ppid, uid=excluded.uid, comm=excluded.comm,
            cmdline=excluded.cmdline, username=excluded.username, seen_at=excluded.seen_at
    `, pid, ppid, uid, comm, cmdline, username, time.Now().Unix())
	if err != nil {
		log.Printf("upsert pid=%d: %v", pid, err)
	}
}

type lineage struct {
	comm, cmdline, username string
	ppid                    uint32
	parentComm, parentCmd   string
}

func queryLineage(db *sql.DB, pid uint32) *lineage {
	var l lineage
	err := db.QueryRow(`
        SELECT p.comm, p.cmdline, p.username, p.ppid,
               COALESCE(par.comm,    '[unknown]'),
               COALESCE(par.cmdline, '[unknown]')
        FROM   processes p
        LEFT JOIN processes par ON par.pid = p.ppid
        WHERE  p.pid = ?
    `, pid).Scan(&l.comm, &l.cmdline, &l.username, &l.ppid, &l.parentComm, &l.parentCmd)
	if err != nil {
		return nil
	}
	return &l
}

// ─── /proc helpers ────────────────────────────────────────────────────────────

func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

func resolveUID(uid uint32) string {
	data, _ := os.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		var u uint32
		fmt.Sscanf(parts[2], "%d", &u)
		if u == uid {
			return parts[0]
		}
	}
	return fmt.Sprintf("uid:%d", uid)
}

// ─── Alert ────────────────────────────────────────────────────────────────────

func emitAlert(ev bpfEvent, filename, category string, l *lineage) {
	comm := nullStr(ev.Comm[:])
	ts := time.Now().Format("2006-01-02T15:04:05.000")

	parentComm, parentCmd, username := "[unknown]", "[unknown]", fmt.Sprintf("uid:%d", ev.Uid)
	if l != nil {
		parentComm = l.parentComm
		parentCmd = l.parentCmd
		username = l.username
	}

	fmt.Printf(
		"\n[ALERT] 🚨  %s\n"+
			"  category  = %s\n"+
			"  file      = %s\n"+
			"  pid       = %d  comm=%s\n"+
			"  uid       = %d  (%s)\n"+
			"  ppid      = %d  parent=%s\n"+
			"  parentcmd = %s\n",
		ts, category, filename,
		ev.Pid, comm,
		ev.Uid, username,
		ev.Ppid, parentComm,
		parentCmd,
	)
}

func nullStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	// ── Load the BPF object from the embedded bytes ──────────────────
	// ebpf.LoadCollectionSpecFromReader parses the ELF .o directly —
	// this is exactly what bpf2go calls internally, just exposed to us.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		log.Fatalf("parse BPF ELF: %v", err)
	}

	// ── Instantiate maps and programs in the kernel ───────────────────
	// LoadAndAssign is the manual equivalent of bpf2go's generated Load func.
	// We define our own struct with field names matching the C identifiers.
	var objs struct {
		// Maps — field name must match the C map variable name exactly
		Events *ebpf.Map `ebpf:"events"`

		// Programs — field name must match the C function name exactly
		HandleExec   *ebpf.Program `ebpf:"handle_exec"`
		HandleOpenat *ebpf.Program `ebpf:"handle_openat"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Events.Close()
	defer objs.HandleExec.Close()
	defer objs.HandleOpenat.Close()

	// ── Attach tracepoints ────────────────────────────────────────────
	execLink, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		log.Fatalf("attach exec tracepoint: %v", err)
	}
	defer execLink.Close()

	openLink, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("attach openat tracepoint: %v", err)
	}
	defer openLink.Close()

	log.Println("tracepoints attached — watching sensitive files")

	// ── SQLite ────────────────────────────────────────────────────────
	db, err := setupDB()
	if err != nil {
		log.Fatalf("setup db: %v", err)
	}
	defer db.Close()

	// ── Ring buffer reader ────────────────────────────────────────────
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	// ── Signal handling ───────────────────────────────────────────────
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		rd.Close()
	}()

	log.Println("listening (Ctrl-C to stop)")
	log.Println(strings.Repeat("─", 60))

	// ── Event loop ────────────────────────────────────────────────────
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		// Deserialise the raw bytes into our Go struct.
		// binary.Read respects struct field order and uses the
		// host byte order (little-endian on x86).
		var ev bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		filename := nullStr(ev.Filename[:])

		switch ev.EventType {
		case EventExec:
			upsertProcess(db, ev.Pid, ev.Ppid, ev.Uid, nullStr(ev.Comm[:]))

		case EventOpen:
			if cat, ok := isSensitive(filename); ok {
				l := queryLineage(db, ev.Pid)
				emitAlert(ev, filename, cat, l)
			}
		}
	}

	log.Println("stopped")
}
