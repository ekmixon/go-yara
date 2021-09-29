// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.
//go:build !yara3.3 && !yara3.4 && !yara3.5 && !yara3.6 && !yara3.7
// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

/*
#include <yara.h>

#ifdef _WIN32
#include <stdint.h>
int _yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    int fd)
{
  return yr_scanner_scan_fd(scanner, (YR_FILE_DESCRIPTOR)(intptr_t)fd);
}
#else
#define _yr_scanner_scan_fd yr_scanner_scan_fd
#endif


YR_RULE_PROFILING_INFO* profiling_info(YR_RULE_PROFILING_INFO* p, int n)
{
  if (p[n].rule == NULL)
    return NULL;
  return &p[n];
}

int scanCallbackFunc(YR_SCAN_CONTEXT*, int, void*, void*);
*/
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

// Scanner contains a YARA scanner (YR_SCANNER). The main difference
// to Rules (YR_RULES) is that it is possible to set variables in a
// thread-safe manner (cf.
// https://github.com/VirusTotal/yara/issues/350).
//
// Since this type contains a C pointer to a YR_SCANNER structure that
// may be automatically freed, it should not be copied.
type Scanner struct {
	cptr *C.YR_SCANNER
	// The Scanner struct has to hold a pointer to the rules
	// it wraps, as otherwise it may be be garbage collected.
	rules *Rules
	// Current callback object, set by SetCallback
	Callback ScanCallback
	// Scan flags are set just before scanning.
	flags ScanFlags
}

func (s *Scanner) newScanError(code C.int) error {
	if code == C.ERROR_SUCCESS {
		return nil
	}
	err := Error{Code: int(code)}
	if rule := s.GetLastErrorRule(); rule != nil {
		err.RuleIdentifier = rule.Identifier()
		err.Namespace = rule.Namespace()
	}
	if str := s.GetLastErrorString(); str != nil {
		err.StringIdentifier = str.Identifier()
	}
	return err
}

// NewScanner creates a YARA scanner.
func NewScanner(r *Rules) (*Scanner, error) {
	var yrScanner *C.YR_SCANNER
	if err := newError(C.yr_scanner_create(r.cptr, &yrScanner)); err != nil {
		return nil, err
	}
	s := &Scanner{cptr: yrScanner, rules: r}
	runtime.SetFinalizer(s, (*Scanner).Destroy)
	return s, nil
}

// Destroy destroys the YARA data structure representing a scanner.
//
// It should not be necessary to call this method directly.
func (s *Scanner) Destroy() {
	if s.cptr != nil {
		C.yr_scanner_destroy(s.cptr)
		s.cptr = nil
	}
	runtime.SetFinalizer(s, nil)
}

// DefineVariable defines a named variable for use by the scanner.
// Boolean, int64, float64, and string types are supported.
func (s *Scanner) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_scanner_define_boolean_variable(
			s.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_scanner_define_integer_variable(
			s.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_scanner_define_float_variable(
			s.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_scanner_define_string_variable(
			s.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	runtime.KeepAlive(s)
	return
}

// SetFlags sets flags for the scanner.
func (s *Scanner) SetFlags(flags ScanFlags) *Scanner {
	s.flags = flags
	return s
}

// SetTimeout sets a timeout for the scanner.
func (s *Scanner) SetTimeout(timeout time.Duration) *Scanner {
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	return s
}

// SetCallback sets a callback object for the scanner. For every event
// emitted by libyara during subsequent scan, the appropriate method
// on the ScanCallback object is called.
//
// For the common case where only a list of matched rules is relevant,
// setting a callback object is not necessary.
func (s *Scanner) SetCallback(cb ScanCallback) *Scanner {
	s.Callback = cb
	return s
}

// putCallbackData stores the scanner's callback object in
// callbackData, returning a pointer. If no callback object has been
// set, it is initialized with the pointer to an empty ScanRules
// object. The object must be removed from callbackData by the calling
// ScanXxxx function.
func (s *Scanner) putCallbackData() unsafe.Pointer {
	if _, ok := s.Callback.(ScanCallback); !ok {
		s.Callback = &MatchRules{}
	}
	ptr := callbackData.Put(makeScanCallbackContainer(s.Callback, s.rules))
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), ptr)
	return ptr
}

// ScanMem scans an in-memory buffer using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanMem(buf []byte) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	cbPtr := s.putCallbackData()
	defer callbackData.Delete(cbPtr)

	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C.yr_scanner_scan_mem(
		s.cptr,
		ptr,
		C.size_t(len(buf))))

	runtime.KeepAlive(s)
	return
}

// ScanFile scans a file using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanFile(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))

	cbPtr := s.putCallbackData()
	defer callbackData.Delete(cbPtr)

	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C.yr_scanner_scan_file(
		s.cptr,
		cfilename,
	))
	runtime.KeepAlive(s)
	return
}

// ScanFileDescriptor scans a file using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanFileDescriptor(fd uintptr) (err error) {
	cbPtr := s.putCallbackData()
	defer callbackData.Delete(cbPtr)

	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C._yr_scanner_scan_fd(
		s.cptr,
		C.int(fd),
	))
	runtime.KeepAlive(s)
	return
}

// ScanProc scans a live process using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanProc(pid int) (err error) {
	cbPtr := s.putCallbackData()
	defer callbackData.Delete(cbPtr)

	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C.yr_scanner_scan_proc(
		s.cptr,
		C.int(pid),
	))
	runtime.KeepAlive(s)
	return
}

// ScahMemBlocks scans over a MemoryBlockIterator using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanMemBlocks(mbi MemoryBlockIterator) (err error) {
	c := makeMemoryBlockIteratorContainer(mbi)
	defer c.free()
	cmbi := makeCMemoryBlockIterator(c)
	defer callbackData.Delete(cmbi.context)

	cbPtr := s.putCallbackData()
	defer callbackData.Delete(cbPtr)

	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = newError(C.yr_scanner_scan_mem_blocks(
		s.cptr,
		cmbi,
	))
	runtime.KeepAlive(s)
	return
}

// GetLastErrorRule returns the rule that caused the last scanner error.
func (s *Scanner) GetLastErrorRule() *Rule {
	r := C.yr_scanner_last_error_rule(s.cptr)
	if r == nil {
		return nil
	}
	return &Rule{r, s.rules}
}

// GetLastErrorString returns the string that caused the last scanner error.
func (s *Scanner) GetLastErrorString() *String {
	str := C.yr_scanner_last_error_string(s.cptr)
	if str == nil {
		return nil
	}
	return &String{str, s.rules}
}

type ProfilingInfo struct {
	Rule *Rule
	Cost uint64
}

// GetProfilingInfo returns a list of ProfilingInfo structures containing the
// profiling information for the slowest n rules.
func (s *Scanner) GetProfilingInfo(n int) (result []ProfilingInfo) {
	pi := C.yr_scanner_get_profiling_info(s.cptr)
	if pi == nil {
		return
	}
	for i := 0; i < n; i++ {
		p := C.profiling_info(pi, C.int(i))
		if p == nil {
			break
		}
		result = append(result,
			ProfilingInfo{
				&Rule{p.rule, s.rules},
				uint64(p.cost)})
	}
	C.yr_free(unsafe.Pointer(pi))
	return result
}

// ResetProfilingInfo resets the profiling information accumulated by the scanner
// so far. When you scan multiple files/buffer with the same scanner the profiling
// information is not automatically reset after each scan, instead it gets
// accumulated. If you want to reset profiling information so that the counters
// start a zero again you must call this function.
func (s *Scanner) ResetProfilingInfo() {
	C.yr_scanner_reset_profiling_info(s.cptr)
}
