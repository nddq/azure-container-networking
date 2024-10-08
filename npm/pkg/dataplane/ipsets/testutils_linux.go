package ipsets

import testutils "github.com/Azure/azure-container-networking/test/utils"

var (
	ipsetRestoreStringSlice = []string{"ipset", "restore"}
	ipsetSaveStringSlice    = []string{"ipset", "save"}

	fakeRestoreSuccessCommand = testutils.TestCmd{
		Cmd:      ipsetRestoreStringSlice,
		Stdout:   "success",
		ExitCode: 0,
	}

	fakeRestoreFailureCommand = testutils.TestCmd{
		Cmd:      ipsetRestoreStringSlice,
		Stdout:   "failure",
		ExitCode: 1,
	}
)

func GetApplyIPSetsTestCalls(toAddOrUpdateIPSets, toDeleteIPSets []*IPSetMetadata) []testutils.TestCmd {
	if len(toAddOrUpdateIPSets) == 0 && len(toDeleteIPSets) == 0 {
		return []testutils.TestCmd{}
	}
	return []testutils.TestCmd{fakeRestoreSuccessCommand}
}

func GetApplyIPSetsFailureTestCalls() []testutils.TestCmd {
	return []testutils.TestCmd{
		fakeRestoreFailureCommand,
		fakeRestoreFailureCommand,
		fakeRestoreFailureCommand,
		fakeRestoreFailureCommand,
		fakeRestoreFailureCommand,
	}
}

func GetResetTestCalls() []testutils.TestCmd {
	return []testutils.TestCmd{
		{Cmd: []string{"ipset", "list", "--name"}, PipedToCommand: true},
		{Cmd: []string{"grep", "-q", "-v", "azure-npm-"}, ExitCode: 1}, // grep didn't find anything
		{Cmd: []string{"bash", "-c", "ipset flush && ipset destroy"}},
	}
}
