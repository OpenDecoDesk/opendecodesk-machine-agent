package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	taskName     = appName
	runKey       = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	uninstallKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenDecoDeskMachineAgent`

	createNoWindow  = 0x08000000
	detachedProcess = 0x00000008
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
)

func platformDataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserCacheDir()
	}
	return filepath.Join(base, appName)
}

func binaryName() string { return appName + ".exe" }

func logFilePath() string { return filepath.Join(dataDir(), "agent.log") }

// prepareConsole: the release program is a windowed (GUI) program, so a double-click never flashes
// a console window. Run from a command prompt with options, it borrows that console for its output.
func prepareConsole(cli bool) {
	if !cli {
		return
	}
	h, _ := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if h != 0 && h != syscall.InvalidHandle {
		return // output already goes somewhere (a console program, or redirected)
	}
	const attachParent = ^uintptr(0) // ATTACH_PARENT_PROCESS
	if r, _, _ := kernel32.NewProc("AttachConsole").Call(attachParent); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
		logOut = f
	}
}

// The service has no console: its output goes to agent.log in the agent's folder.
func openServiceLog() {
	if testInstall() {
		return // tests read the output, and delete the folder while this still runs
	}
	truncateIfLarge(logFilePath())
	if f, err := os.OpenFile(logFilePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		logOut = f
		os.Stdout, os.Stderr = f, f
	}
}

// hidden runs a console tool without flashing its window.
func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

func xmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func taskXML(target, userID string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Lets your OpenDecoDesk admin site use the embroidery machines on this network.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlText(userID) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlText(userID) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"` + xmlText(target) + `"</Command>
      <Arguments>run</Arguments>
      <WorkingDirectory>` + xmlText(filepath.Dir(target)) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
}

func utf16File(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := []byte{0xFF, 0xFE}
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// registerService starts the agent at every logon through Task Scheduler (restarted within a
// minute if it ever stops), as this user, without admin rights. If Task Scheduler refuses, the
// Run key in the registry starts it at logon instead. Either way it's started now, and listed in
// Settings → Apps so it can be removed the usual way.
func registerService(target string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	xmlPath := filepath.Join(dataDir(), "task.xml")
	if err := os.WriteFile(xmlPath, utf16File(taskXML(target, u.Username)), 0o600); err != nil {
		return err
	}
	defer os.Remove(xmlPath)
	out, err := hidden("schtasks", "/Create", "/TN", taskName, "/XML", xmlPath, "/F").CombinedOutput()
	if err == nil {
		hidden("reg", "delete", runKey, "/v", appName, "/f").Run()
		if out, err := hidden("schtasks", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
			return fmt.Errorf("schtasks /Run: %v %s", err, strings.TrimSpace(string(out)))
		}
	} else {
		logf("Task Scheduler refused the task (%v %s); using the Run key instead.", err, strings.TrimSpace(string(out)))
		if out, err := hidden("reg", "add", runKey, "/v", appName, "/t", "REG_SZ", "/d", `"`+target+`" run`, "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("reg add: %v %s", err, strings.TrimSpace(string(out)))
		}
		cmd := exec.Command(target, "run")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: detachedProcess | createNoWindow}
		if err := cmd.Start(); err != nil {
			return err
		}
		cmd.Process.Release()
	}
	for _, kv := range [][]string{
		{"DisplayName", "REG_SZ", appName},
		{"DisplayVersion", "REG_SZ", version},
		{"Publisher", "REG_SZ", "OpenDecoDesk"},
		{"DisplayIcon", "REG_SZ", target},
		{"InstallLocation", "REG_SZ", filepath.Dir(target)},
		{"UninstallString", "REG_SZ", `"` + target + `" uninstall`},
		{"NoModify", "REG_DWORD", "1"},
		{"NoRepair", "REG_DWORD", "1"},
	} {
		hidden("reg", "add", uninstallKey, "/v", kv[0], "/t", kv[1], "/d", kv[2], "/f").Run()
	}
	return nil
}

// stopService ends the running agent (but not this process, which may be the agent itself).
func stopService() {
	hidden("schtasks", "/End", "/TN", taskName).Run()
	hidden("taskkill", "/F", "/FI", "PID ne "+strconv.Itoa(os.Getpid()), "/IM", binaryName()).Run()
	for i := 0; i < 20; i++ {
		if running, _ := pingAgent(); running == "" {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func unregisterService() error {
	hidden("schtasks", "/Delete", "/TN", taskName, "/F").Run()
	hidden("reg", "delete", runKey, "/v", appName, "/f").Run()
	hidden("reg", "delete", uninstallKey, "/f").Run()
	return nil
}

// removeInstalledFiles deletes the agent's folder. A running program's file can't be deleted on
// Windows, so when this program runs from that folder, a hidden command prompt deletes it a few
// seconds after this process ends.
func removeInstalledFiles(bool) {
	self, _ := executable()
	if !strings.HasPrefix(strings.ToLower(self), strings.ToLower(dataDir()+string(os.PathSeparator))) {
		os.RemoveAll(dataDir())
		return
	}
	cmd := exec.Command(os.Getenv("ComSpec"))
	if cmd.Path == "" {
		cmd = exec.Command("cmd.exe")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNoWindow,
		CmdLine:       `/C ping -n 4 127.0.0.1 >NUL & rmdir /S /Q "` + dataDir() + `"`,
	}
	if cmd.Start() == nil {
		cmd.Process.Release()
	}
}

func migrateOldInstall(*settings) {} // the Python agent had no Windows installer

func openBrowser(url string) {
	hidden("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func showMessage(title, msg string, isError bool) {
	const mbOK, mbIconError, mbIconInfo, mbSetForeground = 0x0, 0x10, 0x40, 0x10000
	flags := uintptr(mbOK | mbSetForeground | mbIconInfo)
	if isError {
		flags = uintptr(mbOK | mbSetForeground | mbIconError)
	}
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(msg)
	user32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
}
