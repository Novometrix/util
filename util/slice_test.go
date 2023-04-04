package util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSliceContains_String(t *testing.T) {
	type Params struct {
		Slice    []string
		Expected string
	}
	tests := []struct {
		name string
		Params
		expected bool
	}{
		{
			name: "success_true",
			Params: Params{
				Slice: []string{
					testString,
					testString + testString,
				},
				Expected: testString,
			},
			expected: true,
		},
		{
			name: "success_false",
			Params: Params{
				Slice: []string{
					testString + testString,
					testString + testString + testString,
				},
				Expected: testString,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := SliceContains(tt.Params.Slice, tt.Params.Expected)

			assert.EqualValues(t, tt.expected, resp)
		})
	}
}

func TestSliceContains_Int(t *testing.T) {
	type Params struct {
		Slice    []int
		Expected int
	}
	tests := []struct {
		name string
		Params
		expected bool
	}{
		{
			name: "success_true",
			Params: Params{
				Slice: []int{
					testInt,
					testInt + testInt,
				},
				Expected: testInt,
			},
			expected: true,
		},
		{
			name: "success_false",
			Params: Params{
				Slice: []int{
					testInt + testInt,
					testInt + testInt + testInt,
				},
				Expected: testInt,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := SliceContains(tt.Params.Slice, tt.Params.Expected)

			assert.EqualValues(t, tt.expected, resp)
		})
	}
}
