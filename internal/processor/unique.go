package processor

type Hashible interface {
	GetID() string
}

func unique[T Hashible](list []T) []T {
	seen := map[string]bool{}
	result := make([]T, 0)
	for _, item := range list {
		h := item.GetID()
		if !seen[h] {
			seen[h] = true
			result = append(result, item)
		}
	}
	return result
}
