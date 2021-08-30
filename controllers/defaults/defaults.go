// Package defaults contains the default values for various configurable options
package defaults

import (
	"strconv"
	"strings"
)

const ()

var (
	// ScanningInterval is the number of seconds to wait before the controller starts again
	ScanningInterval = 30
)

// setDefaultInt32 will return either the default int32 or an overriden value
func SetDefaultInt32(defaultVal int32, overrideVal int32) int32 {
	iString := strings.TrimSpace(i32ToString(overrideVal))
	if overrideVal == 0 {
		return defaultVal
	}
	if len(iString) > 0 {
		return overrideVal
	}
	return defaultVal
}

// setDefaultInt will return either the default int or an overriden value
func SetDefaultInt(defaultVal int, overrideVal int) int {
	if overrideVal == 0 {
		return defaultVal
	}
	if len(strings.TrimSpace(strconv.Itoa(overrideVal))) > 0 {
		return overrideVal
	}
	return defaultVal
}

// setDefaultString will return either the default string or an overriden value
func SetDefaultString(defaultVal string, overrideVal string) string {
	if len(strings.TrimSpace(overrideVal)) > 0 {
		return overrideVal
	}
	return defaultVal
}

// i32ToString will convert an int32 to a string for length comparison
func i32ToString(n int32) string {
	buf := [11]byte{}
	pos := len(buf)
	i := int64(n)
	signed := i < 0
	if signed {
		i = -i
	}
	for {
		pos--
		buf[pos], i = '0'+byte(i%10), i/10
		if i == 0 {
			if signed {
				pos--
				buf[pos] = '-'
			}
			return string(buf[pos:])
		}
	}
}
