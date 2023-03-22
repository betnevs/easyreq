package easyreq

type Response struct {
}

func (r *Response) IsError() bool {
	return false
}
