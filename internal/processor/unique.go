package processor

type Hashible interface {
	GetSHA256() string
}

func Unique[T Hashible](list []T) []T {
	seen := map[string]bool{}
	result := make([]T, 0)
	for _, item := range list {
		h := item.GetSHA256()
		if !seen[h] {
			seen[h] = true
			result = append(result, item)
		}
	}
	return result
}
