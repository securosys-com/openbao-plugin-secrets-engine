package tests

import (
	"fmt"
	"os"
	"sync"
	"testing"

	testHelpers "securosys.ch/test-helpers"
)

var (
	sharedTestEnv     *testHelpers.TestEnv
	sharedTestEnvErr  error
	sharedTestEnvOnce sync.Once
)

func getSharedTestEnv(t *testing.T) *testHelpers.TestEnv {
	t.Helper()
	testHelpers.RequireTSBConfig(t)

	sharedTestEnvOnce.Do(func() {
		sharedTestEnv, sharedTestEnvErr = testHelpers.NewTestEnv()
		if sharedTestEnvErr != nil {
			return
		}
		if sharedTestEnvErr = sharedTestEnv.AddConfigRaw(); sharedTestEnvErr != nil {
			return
		}
		if sharedTestEnvErr = sharedTestEnv.PrepareTestKeysRaw(); sharedTestEnvErr != nil {
			_ = sharedTestEnv.RemoveTestKeysRaw()
		}
	})

	if sharedTestEnvErr != nil {
		t.Fatal(sharedTestEnvErr)
	}
	return sharedTestEnv
}

func TestMain(m *testing.M) {
	code := m.Run()

	if sharedTestEnv != nil {
		if err := sharedTestEnv.RemoveTestKeysRaw(); err != nil {
			fmt.Fprintf(os.Stderr, "shared test key cleanup failed: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}

	os.Exit(code)
}
