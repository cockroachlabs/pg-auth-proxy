// Code generated by "stringer -type=closeReason"; DO NOT EDIT.

package conn

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[terminateFromClient-0]
	_ = x[drainConnection-1]
	_ = x[generalError-2]
}

const _closeReason_name = "terminateFromClientdrainConnectiongeneralError"

var _closeReason_index = [...]uint8{0, 19, 34, 46}

func (i closeReason) String() string {
	if i < 0 || i >= closeReason(len(_closeReason_index)-1) {
		return "closeReason(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _closeReason_name[_closeReason_index[i]:_closeReason_index[i+1]]
}
