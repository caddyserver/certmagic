package testutil

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func AssertNoError(t *testing.T, err error, msgAndArgs ...string) {
	if err != nil {
		Fail(t, fmt.Sprintf("Received unexpected error:\n%+v", err), msgAndArgs...)
	}
}

func AssertEqual(t *testing.T, a, b any, msgAndArgs ...string) {
	if !ObjectsAreEqual(a, b) {
		Fail(t, fmt.Sprintf("Not equal: \n"+
			"expected: %v\n"+
			"actual  : %v", a, b), msgAndArgs...)
	}
}
func RequireNoError(t *testing.T, err error, msgAndArgs ...string) {
	if err != nil {
		Failnow(t, fmt.Sprintf("Received unexpected error:\n%+v", err), msgAndArgs...)
	}
}
func RequireError(t *testing.T, err error, msgAndArgs ...string) {
	if err == nil {
		Failnow(t, fmt.Sprintf("Received no error when expecting error:\n%+v", err), msgAndArgs...)
	}
}

func RequireEqual(t *testing.T, a, b any, msgAndArgs ...string) {
	if !ObjectsAreEqual(a, b) {
		Failnow(t, fmt.Sprintf("Not equal: \n"+
			"expected: %v\n"+
			"actual  : %v", a, b), msgAndArgs...)
	}
}
func RequireEqualValues(t *testing.T, a, b any, msgAndArgs ...string) {
	if !ObjectsAreEqualValues(a, b) {
		Failnow(t, fmt.Sprintf("Not equal: \n"+
			"expected: %v\n"+
			"actual  : %v", a, b), msgAndArgs...)
	}
}

func Fail(t testing.TB, xs string, msgs ...string) {
	var testName string
	// Add test name if the Go version supports it
	if n, ok := t.(interface {
		Name() string
	}); ok {
		testName = n.Name()
	}

	t.Errorf("error %s:%s\n%s\n", testName, xs, strings.Join(msgs, ""))
}

func Failnow(t testing.TB, xs string, msgs ...string) {
	Fail(t, xs, msgs...)
	t.FailNow()
}

func ObjectsAreEqual(expected, actual any) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}

	exp, ok := expected.([]byte)
	if !ok {
		return reflect.DeepEqual(expected, actual)
	}

	act, ok := actual.([]byte)
	if !ok {
		return false
	}
	if exp == nil || act == nil {
		return exp == nil && act == nil
	}
	return bytes.Equal(exp, act)
}

func ObjectsAreEqualValues(expected, actual any) bool {
	if ObjectsAreEqual(expected, actual) {
		return true
	}

	actualType := reflect.TypeOf(actual)
	if actualType == nil {
		return false
	}
	expectedValue := reflect.ValueOf(expected)
	if expectedValue.IsValid() && expectedValue.Type().ConvertibleTo(actualType) {
		// Attempt comparison after type conversion
		return reflect.DeepEqual(expectedValue.Convert(actualType).Interface(), actual)
	}

	return false
}
