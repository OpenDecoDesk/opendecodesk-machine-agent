package main

// The machines' own protocol: discovery, listing, sending a design and reading a file back.
// These are "SmartStitch"-branded machines with Raynen controllers. They are NOT plain FTP
// servers: everything here was reverse-engineered from Wireshark captures of the vendor's own
// software talking to a machine. Full reference: PROTOCOL.md.
//
//   - Discovery (§2): a UDP broadcast on port 23 with a fixed 4-byte payload; each machine on the
//     LAN replies with its MAC (bytes 9:15) and two NUL-terminated strings — firmware at byte 19
//     and, at byte 51, the name entered on the machine (returned as "model").
//   - Every TCP frame (§1), on port 6000, both ways:  fa 01 <len16 LE> <body> <lrc>  where len16
//     is len(body)+1 and <lrc> is the XOR of all preceding bytes in the frame.
//   - Listing (§3): one JSON document ({"num":N,"files":[…]}) split across framed pages.
//   - Upload (§4): register the filename (cf25), then stream the bytes 1024 per page (cf23).
//   - Read back (§8): the upload in reverse — name the file in cf22, the machine streams cf23.
//   - Delete (§6): the firmware has the command (cf24) but refuses every use of it.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// opError is a failure with a message safe to show the operator (HTTP 502). Anything else that
// goes wrong is reported as "Unexpected error" (HTTP 500).
type opError struct{ msg string }

func (e *opError) Error() string { return e.msg }

func opErr(format string, a ...any) error { return &opError{fmt.Sprintf(format, a...)} }

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

const (
	downloadTimeout  = 30 * time.Second
	maxDownloadBytes = 20 * 1024 * 1024
)

// ---- Machine discovery (UDP broadcast) --------------------------------------------------
const (
	udpBroadcastIP = "255.255.255.255"
	udpTargetPort  = 23 // machine's listening discovery port
	// The machines answer whatever port the scan is sent FROM, so any free port works (0 = let the
	// system pick). A fixed one (the vendor's app uses 60023) can be held by another program or
	// reserved by Windows (Hyper-V reserves ranges of high ports), which made binding fail with
	// WinError 10013 and the scan never ran.
	udpListenPort   = 0
	discoveryWindow = 1500 * time.Millisecond
)

var discoveryPayload = []byte{0xFF, 0x04, 0x02, 0xFB}

// ---- File listing (TCP, port 6000) ------------------------------------------------------
var tcpListPort = 6000 // a var only so test builds can point it at a stub (testhooks_on.go)

const (
	listConnectTimeout = 2 * time.Second
	listPageRead       = 2 * time.Second
	maxListPages       = 64 // ~1024 JSON bytes/page, ~14 files/page -> safety cap well above any real machine
	// (we stop early anyway once the machine's declared `num` files are all in)
)

// ---- Sending a design (TCP, port 6000) --------------------------------------------------
// Reverse-engineered byte-for-byte from a real Wireshark capture of the vendor's own software
// uploading a design, cross-checked against several more captures made on purpose (files named
// A.DST/B.DST/AA.DST/BB.DST specifically to expose how the trailing byte is built).
//
// Upload sequence, straight from the capture:
//  1. Register the filename:  body = 01 00 cf 25 00 <filename ASCII>
//     -> machine replies with a cf 22 frame echoing the name.
//  2. Send the raw design-file bytes in order, 1024 bytes per "page" (pages numbered from 1):
//     body = 01 00 cf 23 <page16 LE> <totalBlocks16 LE> <up to 1024 file bytes>
//     -> machine replies with a short cf 22 ack ("ready for the next page") after each block
//     EXCEPT the last, after which it just commits the file and TCP-acks (no cf 22). Waiting for a
//     cf 22 on the final block makes a whole, already-landed send look like it "timed out". The
//     LAST block carries only the remaining bytes and is NOT padded. The <totalBlocks> field is
//     constant for the whole file (ceil(size/1024)); the machine uses it to know when the
//     transfer is complete and to commit the file — captures showed 0x0032 (50) for a 50-block
//     file and 0x0016 (22) for a 22-block one. Getting it wrong makes the machine wait forever for
//     blocks that never come (declared too many) or reject the block past the declared count with
//     a cf e1 error.
const (
	sendConnectTimeout = 3 * time.Second
	sendAckTimeout     = 6 * time.Second
	sendChunkBytes     = 1024
	errorStatusByte    = 0xC9 // seen in a cf22 status frame when the machine rejects a transfer
)

// Reading a file back: what the machine sends is its stored form (a DST-style header followed by
// Barudan records), so it's named .DSB whatever was uploaded.
const (
	readExt       = "DSB"
	maxReadBlocks = maxDownloadBytes / sendChunkBytes
)

const deleteUnsupportedMessage = "Deleting a file isn't supported by this machine's firmware " +
	"(the delete command, cf24, is present but disabled) — clear files " +
	"at the touchscreen. See PROTOCOL.md §6."

// The signed design link never redirects; refusing redirects keeps a validated URL from being
// bounced somewhere else (another host, or another scheme).
func noRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var downloadClient = noRedirectClient(downloadTimeout)

// fetchDesignFile downloads the design file from the signed admin link.
func fetchDesignFile(downloadURL string) ([]byte, error) {
	if problem := validateDownloadURL(downloadURL); problem != "" {
		return nil, opErr("%s", problem)
	}
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return nil, opErr("Invalid download link.")
	}
	req.Header.Set("User-Agent", agentName+"/"+agentVersion)
	resp, err := downloadClient.Do(req)
	if err != nil {
		if isTimeout(err) {
			return nil, opErr("Timed out downloading the design file.")
		}
		return nil, opErr("Could not reach the download link: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, opErr("Download link has expired — reopen the screen and try again.")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, opErr("Could not download the design file (HTTP %d).", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		if isTimeout(err) {
			return nil, opErr("Timed out downloading the design file.")
		}
		return nil, opErr("Could not reach the download link: %v", err)
	}
	if len(data) > maxDownloadBytes {
		return nil, opErr("Design file is larger than expected — refusing to send.")
	}
	if len(data) == 0 {
		return nil, opErr("Downloaded file was empty.")
	}
	return data, nil
}

type machine struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
}

// discoverMachines broadcasts the discovery payload on the LAN and collects replies for `window`,
// one per distinct IP that answered. The replies come back to the port the scan was sent from,
// which is any free one (see udpListenPort). targetPort/listenPort/broadcastIP are the real values
// except in tests, which point this at a throwaway stub on a high, unprivileged port addressed
// directly (loopback broadcast isn't reliable across platforms).
func discoverMachines(targetPort, listenPort int, window time.Duration, broadcastIP string) ([]machine, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: listenPort})
	if err != nil {
		return nil, opErr("Could not open a network port to hear the machines' replies: %v", err)
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.ParseIP(broadcastIP), Port: targetPort}
	if dst.IP == nil {
		return nil, opErr("Not an IP address: %q", broadcastIP)
	}
	// Go sets SO_BROADCAST on UDP sockets itself.
	if _, err := conn.WriteToUDP(discoveryPayload, dst); err != nil {
		return nil, opErr("Could not send the machine scan: %v", err)
	}

	machines := []machine{}
	seen := map[string]bool{}
	deadline := time.Now().Add(window)
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 1024)
	for time.Now().Before(deadline) {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				break
			}
			// e.g. Windows reports an ICMP "port unreachable" from an earlier send as an error on
			// the next read; it says nothing about the replies still on their way.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		ip := addr.IP.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		data := buf[:n]

		// Real reply layout, confirmed against two different machines (a 1201 Plus and a 1501
		// Ultra): MAC at bytes 9:15, then a NUL-terminated firmware string starting at byte 19, then
		// a NUL-terminated string starting at byte 51 — the name entered on the machine (kept as
		// "model", but not a model number). Both string fields are variable length (firmware
		// prefixes seen so far: "JD…", "HH1S…"), so they must be read as NUL-terminated strings,
		// not sliced at a fixed end offset.
		m := machine{IP: ip, Firmware: cString(data, 19), Model: cString(data, 51)}
		if len(data) >= 15 {
			parts := make([]string, 6)
			for i, b := range data[9:15] {
				parts[i] = fmt.Sprintf("%02X", b)
			}
			m.MAC = strings.Join(parts, ":")
		}
		if m.Model == "" {
			m.Model = "SmartStitch Node"
		}
		machines = append(machines, m)
	}
	return machines, nil
}

func cString(buf []byte, start int) string {
	if start >= len(buf) {
		return ""
	}
	s := buf[start:]
	if i := strings.IndexByte(string(s), 0); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(s), ""))
}

// lrc is the trailing check byte on every frame in this protocol: XOR of all preceding bytes.
func lrc(frameWithoutTrailer []byte) byte {
	var x byte
	for _, b := range frameWithoutTrailer {
		x ^= b
	}
	return x
}

// frame wraps a body in the protocol's envelope: fa 01 <len16 LE> <body> <lrc>.
func frame(body []byte) []byte {
	n := len(body) + 1
	head := append([]byte{0xFA, 0x01, byte(n), byte(n >> 8)}, body...)
	return append(head, lrc(head))
}

// buildListCommand is the 11-byte command frame requesting one page of a machine's file listing:
// the fixed header `fa 01 07 00 01 00 cf 21`, the page number, `00`, and the frame's LRC. (An
// earlier version wrote the last byte as `0x13 - page`, which equals the LRC only for pages 1–3,
// so machines with more than ~3 pages of files couldn't be fully listed.)
func buildListCommand(page int) []byte {
	return frame([]byte{0x01, 0x00, 0xCF, 0x21, byte(page), 0x00})
}

// recvFrame reads one whole reply frame (fa 01 <len16> <body+lrc>) within timeout. It returns
// (nil, nil) if the machine closed the connection or sent an unparseable header, and the error
// (check isTimeout) if the read timed out or failed.
func recvFrame(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil
		}
		return nil, err
	}
	if header[0] != 0xFA || header[1] != 0x01 {
		return nil, nil
	}
	body := make([]byte, int(header[2])|int(header[3])<<8)
	n, err := io.ReadFull(conn, body)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return append(header, body[:n]...), nil
}

func writeAll(conn net.Conn, b []byte, timeout time.Duration) error {
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(b)
	return err
}

// replyIsError: a cf22 status reply signals rejection with the error byte in its status slot.
func replyIsError(f []byte) bool {
	if len(f) < 10 || f[6] != 0xCF || f[7] != 0x22 {
		return false
	}
	end := 11
	if len(f) < end {
		end = len(f)
	}
	for _, b := range f[8:end] {
		if b == errorStatusByte {
			return true
		}
	}
	return false
}

func hexOrNone(f []byte, none string) string {
	if f == nil {
		return none
	}
	return hex.EncodeToString(f)
}

func dialMachine(machineIP string, port int, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(machineIP, strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, opErr("Could not connect to %s: %v", machineIP, err)
	}
	return conn, nil
}

type listedFile struct {
	Name     any `json:"name"`
	Size     any `json:"size"`
	Modified any `json:"modified"`
}

// listMachineDir fetches a machine's file list over one TCP connection.
//
// The machine returns the listing as a single JSON document ({"num":N,"files":[{name,size,date},
// ...]}) split across "pages": each page is a framed response
// `fa 01 <len16> 01 00 cf 26 <page16 LE> <field16> <JSON chunk> <lrc>` carrying up to 1024 bytes of
// the JSON byte-stream. The split happens at arbitrary byte boundaries (mid-object, even mid-key),
// so the pages CANNOT be parsed independently — we strip each page's 12-byte prefix and its 1-byte
// trailing LRC, concatenate the raw JSON chunks, and parse the whole thing once.
func listMachineDir(machineIP string, port int) ([]listedFile, error) {
	conn, err := dialMachine(machineIP, port, listConnectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	time.Sleep(150 * time.Millisecond) // matches the reference capture's timing between connect and first command

	var joined []byte
	for page := 1; page <= maxListPages; page++ {
		if err := writeAll(conn, buildListCommand(page), listPageRead); err != nil {
			return nil, err
		}
		f, err := recvFrame(conn, listPageRead)
		if err != nil {
			if isTimeout(err) {
				break
			}
			return nil, err
		}
		if f == nil || len(f) <= 13 { // a header-only / empty frame = no more pages
			break
		}
		joined = append(joined, f[12:len(f)-1]...) // drop the 12-byte prefix and the trailing LRC byte
		// Stop as soon as the concatenated JSON is complete (all `num` files present), so we don't
		// wait on a trailing empty page.
		if files, num, ok := parseListing(joined); ok && float64(len(files)) >= num {
			break
		}
	}
	files, _, ok := parseListing(joined)
	out := []listedFile{}
	if !ok {
		return out, nil
	}
	for _, f := range files {
		name := f["name"]
		if name == nil {
			name = ""
		}
		out = append(out, listedFile{Name: name, Size: f["size"], Modified: f["date"]})
	}
	return out, nil
}

func parseListing(raw []byte) (files []map[string]any, num float64, ok bool) {
	dec := json.NewDecoder(strings.NewReader(strings.ToValidUTF8(string(raw), "")))
	dec.UseNumber()
	var doc struct {
		Num   json.Number      `json:"num"`
		Files []map[string]any `json:"files"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, 0, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, false // trailing garbage: still incomplete
	}
	num, _ = doc.Num.Float64()
	return doc.Files, num, true
}

type sendResult struct {
	FileName string `json:"fileName"`
	Bytes    int    `json:"bytes"`
	Blocks   int    `json:"blocks"`
}

// sendDesignToMachine uploads a design file over the machines' real protocol (see the comment by
// the send constants for the full derivation).
func sendDesignToMachine(machineIP, fileName string, file []byte, port int) (*sendResult, error) {
	for i := 0; i < len(fileName); i++ {
		if fileName[i] >= 0x80 {
			return nil, opErr("Machine filenames must be plain ASCII — rename the design's machine file.")
		}
	}
	if fileName == "" {
		return nil, opErr("No machine filename to register with the machine.")
	}
	total := len(file)
	totalBlocks := (total + sendChunkBytes - 1) / sendChunkBytes
	logf("SEND start: %s:%d file=%q %d bytes -> %d blocks", machineIP, port, fileName, total, totalBlocks)

	conn, err := dialMachine(machineIP, port, sendConnectTimeout)
	if err != nil {
		logf("SEND fail: %v", err)
		return nil, err
	}
	defer conn.Close()

	res, err := sendBlocks(conn, fileName, file, totalBlocks)
	if err != nil && isTimeout(err) {
		logf("SEND fail: timed out waiting for the machine")
		return nil, opErr("Timed out waiting for the machine during the transfer.")
	}
	return res, err
}

func sendBlocks(conn net.Conn, fileName string, file []byte, totalBlocks int) (*sendResult, error) {
	time.Sleep(150 * time.Millisecond) // match the capture's pause between connect and first frame

	// 1. Register the filename.
	registration := frame(append([]byte{0x01, 0x00, 0xCF, 0x25, 0x00}, fileName...))
	logf("  -> registration (%d B): %x", len(registration), registration)
	if err := writeAll(conn, registration, sendAckTimeout); err != nil {
		return nil, err
	}
	ack, err := recvFrame(conn, sendAckTimeout)
	if err != nil {
		return nil, err
	}
	logf("  <- registration reply: %s", hexOrNone(ack, "(none)"))
	if ack == nil {
		return nil, opErr("Machine did not acknowledge the filename (no reply). Make sure the " +
			"vendor's own app is closed and the machine is idle.")
	}
	if replyIsError(ack) {
		return nil, opErr("Machine rejected the filename registration.")
	}

	// 2. Stream the raw file bytes, 1024 per page, pages numbered from 1. Last chunk is short.
	//    Every data frame declares the TOTAL block count (little-endian, constant per file) in the
	//    two bytes after the page number — the machine uses it to know when the transfer is
	//    complete and to commit the file.
	// The machine cf22-acks every block with "ready for the next page" — EXCEPT the final block,
	// after which it just commits the file and TCP-acks (no cf22 frame). So we wait for an ack on
	// every block but the last; waiting on the last is what made whole sends "time out" even though
	// the file had already landed.
	for page, offset := 1, 0; offset < len(file); page++ {
		chunk := file[offset:min(offset+sendChunkBytes, len(file))]
		body := append([]byte{0x01, 0x00, 0xCF, 0x23, byte(page), byte(page >> 8), byte(totalBlocks), byte(totalBlocks >> 8)}, chunk...)
		if err := writeAll(conn, frame(body), sendAckTimeout); err != nil {
			return nil, err
		}
		if page == totalBlocks {
			// No cf22 ack expected. Peek briefly only to catch an explicit error reply.
			tail, err := recvFrame(conn, time.Second)
			if err != nil && !isTimeout(err) {
				return nil, err
			}
			logf("  block %d/%d (%d B, final) -> %s", page, totalBlocks, len(chunk), hexOrNone(tail, "no cf22 ack (expected)"))
			if replyIsError(tail) {
				return nil, opErr("Machine rejected the final block of the design.")
			}
			break
		}
		blockAck, err := recvFrame(conn, sendAckTimeout)
		if err != nil {
			return nil, err
		}
		if page == 1 || blockAck == nil || replyIsError(blockAck) {
			logf("  block %d/%d (%d B) <- ack: %s", page, totalBlocks, len(chunk), hexOrNone(blockAck, "(none)"))
		}
		if blockAck == nil {
			return nil, opErr("Transfer stalled after block %d (no acknowledgment).", page)
		}
		if replyIsError(blockAck) {
			return nil, opErr("Machine rejected block %d of the design.", page)
		}
		offset += len(chunk)
	}
	logf("SEND ok: %q delivered in %d blocks", fileName, totalBlocks)
	return &sendResult{FileName: fileName, Bytes: len(file), Blocks: totalBlocks}, nil
}

type readResult struct {
	FileName string
	Data     []byte
	Blocks   int
	Ext      string
}

// readFileFromMachine copies one file off a machine, by the name its listing shows (sequence
// number included, e.g. "LOGO.012"). Decoded from a Wireshark capture of the vendor's app doing it,
// and checked byte-for-byte against that capture on a real machine:
//
//	-> 01 00 cf 22 01 00 00 <stored name UTF-8>        (the shape of the upload-registration echo)
//	<- 01 00 cf 23 <page16 LE> <totalBlocks16 LE> <up to 1024 bytes>   pages from 1
//	-> 01 00 cf 22 <page+1 16 LE>                      ack each block EXCEPT the last
func readFileFromMachine(machineIP, storedName string, port int) (*readResult, error) {
	if storedName == "" { // the listing JSON is UTF-8; non-ASCII names read fine
		return nil, opErr("No file name to ask the machine for.")
	}
	logf("READ start: %s:%d file=%q", machineIP, port, storedName)
	conn, err := dialMachine(machineIP, port, sendConnectTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res, err := readBlocks(conn, storedName)
	if err != nil && isTimeout(err) {
		logf("READ fail: timed out waiting for the machine")
		return nil, opErr("Timed out waiting for the machine while copying the file.")
	}
	return res, err
}

func readBlocks(conn net.Conn, storedName string) (*readResult, error) {
	time.Sleep(150 * time.Millisecond)
	if err := writeAll(conn, frame(append([]byte{0x01, 0x00, 0xCF, 0x22, 0x01, 0x00, 0x00}, storedName...)), sendAckTimeout); err != nil {
		return nil, err
	}
	var data []byte
	page := 1
	for {
		f, err := recvFrame(conn, sendAckTimeout)
		if err != nil {
			return nil, err
		}
		if f == nil {
			if page == 1 {
				return nil, opErr("The machine didn't send %s. Make sure the vendor's own app is closed and the machine is idle.", storedName)
			}
			return nil, opErr("The machine stopped sending %s after block %d.", storedName, page-1)
		}
		if len(f) < 13 || f[6] != 0xCF || f[7] != 0x23 {
			return nil, opErr("The machine refused to send %s.", storedName)
		}
		if lrc(f[:len(f)-1]) != f[len(f)-1] {
			return nil, opErr("Block %d of %s arrived damaged — try again.", page, storedName)
		}
		gotPage := int(f[8]) | int(f[9])<<8
		total := int(f[10]) | int(f[11])<<8
		if gotPage != page || total < 1 || total > maxReadBlocks {
			return nil, opErr("The machine sent %s out of order — try again.", storedName)
		}
		data = append(data, f[12:len(f)-1]...)
		if page >= total {
			break
		}
		next := page + 1
		if err := writeAll(conn, frame([]byte{0x01, 0x00, 0xCF, 0x22, byte(next), byte(next >> 8)}), sendAckTimeout); err != nil {
			return nil, err
		}
		page++
	}
	if len(data) == 0 {
		return nil, opErr("The machine sent %s empty.", storedName)
	}
	logf("READ ok: %q %d bytes in %d blocks", storedName, len(data), page)
	return &readResult{FileName: storedName, Data: data, Blocks: page, Ext: readExt}, nil
}
