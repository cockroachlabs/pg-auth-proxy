// Copyright 2022 Cockroach Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conn

import (
	"fmt"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgproto3/v2"
	"github.com/pkg/errors"
)

// ErrInvalidToken contains a pgwire error message.
var ErrInvalidToken = ErrorResponsef(
	pgerrcode.InvalidAuthorizationSpecification, "invalid JWT token")

// WrappedError wraps a pgwire ErrorResponse as an error.
type WrappedError struct {
	*pgproto3.ErrorResponse
}

// Error implements error.
func (e *WrappedError) Error() string {
	return e.Message
}

// AsErrorResponse locates a WrappedError within the given error message
// and returns the message. Otherwise, a generic "internal error"
// message will be returned.
func AsErrorResponse(err error) *pgproto3.ErrorResponse {
	if found := (*WrappedError)(nil); errors.As(err, &found) {
		return found.ErrorResponse
	}
	return &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     pgerrcode.InternalError,
		Message:  "an unknown error occurred",
	}
}

// ErrorResponsef is a convenience method to return a WrappedError with a
// basic ErrorResponse.
func ErrorResponsef(code string, format string, args ...interface{}) *WrappedError {
	return &WrappedError{&pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     code,
		Message:  fmt.Sprintf(format, args...),
	}}
}
