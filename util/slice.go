package util

func SliceContains[T comparable](slice []T, expected T) bool {
	for _, v := range slice {
		if v == expected {
			return true
		}
	}
	return false
}
