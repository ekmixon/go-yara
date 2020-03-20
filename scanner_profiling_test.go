// Copyright © 2015-2019 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// This file is built only if the profiling_enabled tag is defined. Example:
//  go test --tags profiling_enabled

// +build profiling_enabled

package yara

import "testing"

func TestProfiling(t *testing.T) {
	s := makeScanner(t,
		`rule test1 { condition: false }
			  rule test2 { condition: for all i in (1..1000) : ( false ) }`)
	var m MatchRules
	if err := s.SetCallback(&m).ScanMem([]byte("dummy")); err != nil {
		t.Errorf("ScanFile: %s", err)
	}
	for i, p := range s.GetProfilingInfo(10) {
		if i == 0 && p.rule.Identifier() != "test2" {
			t.Error("The most expensive rule should be test2")
		}
		if i == 1 && p.rule.Identifier() != "test1" {
			t.Error("The least expensive rule should be test1")
		}
	}

	s.ResetProfilingInfo()

	if s.GetProfilingInfo(1)[0].Cost != 0 {
		t.Error("Profiling information should be 0 after caling ResetProfilingInfo")
	}
}
