package utils

func ContainString(sliceString []string, containString string) bool {
	for _, item := range sliceString {
		if item == containString {
			return true
		}
	}
	return false
}

func IsStringSubSlice(sliceString []string, subSlice []string) bool {
	for _, item := range subSlice {
		if !ContainString(sliceString, item) {
			return false
		}
	}
	return true
}
