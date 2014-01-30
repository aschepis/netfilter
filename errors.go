package netfilter

import(
"fmt"
)

type ErrNotEnoughData struct {
	Size uint32
	Min uint32
}

func (err ErrNotEnoughData) Error() string {
	return fmt.Sprintf("Not enough data to process. Got %v bytes, need at least %v",
		err.Size, err.Min)
}