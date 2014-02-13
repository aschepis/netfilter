package netfilter

func consumeStreamStateFn(bytes int, nextState stateFn) stateFn {
	return func(filter *Filter) stateFn {
		filter.stream.Next(bytes)
		return nextState
	}
}

func readStateFn(bytesToRead int, nextState stateFn) stateFn {
	return func(filter *Filter) stateFn {
		select {
		case quit := <-filter.quit:
			if quit {
				return nil
			}
		case data := <-filter.In:
			bytesRead := len(data)
			filter.stream.Write(data)
			if bytesRead < bytesToRead {
				return readStateFn(bytesToRead-bytesRead, nextState)
			} else {
				return nextState
			}
		}
		return nil
	}
}

func skipStateFn(bytesToRead int, nextState stateFn) stateFn {
	return func(filter *Filter) stateFn {
		select {
		case quit := <-filter.quit:
			if quit {
				return nil
			}
		case data := <-filter.In:
			bytesRead := len(data)
			if bytesRead < bytesToRead {
				return skipStateFn(bytesToRead-bytesRead, nextState)
			} else {
				if bytesRead > bytesToRead {
					filter.stream.Write(data[bytesToRead:])
				}
				return nextState
			}
		}
		return nil
	}
}
