package processor

type Hashible interface {
	GetID() string
}

func unique[T Hashible](list []T) []T {
	seen := make(map[string]bool, len(list))
	result := make([]T, 0, len(list))
	for _, item := range list {
		h := item.GetID()
		if !seen[h] {
			seen[h] = true
			result = append(result, item)
		}
	}
	return result
}
