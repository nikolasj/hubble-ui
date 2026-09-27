package authz

import (
	"net/http"
	"strings"
)

// HeaderIdentity reads the identity that the authentication proxy sets on
// every request it lets through. The first user header that is present wins,
// groups may come in one comma separated header or in repeated headers.
type HeaderIdentity struct {
	UserHeaders     []string
	GroupsHeader    string
	GroupsSeparator string
}

func (h HeaderIdentity) FromHeaders(headers http.Header) (Identity, bool) {
	id := Identity{}

	for _, name := range h.UserHeaders {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			id.User = value
			break
		}
	}

	if id.User == "" {
		return id, false
	}

	if h.GroupsHeader == "" {
		return id, true
	}

	separator := h.GroupsSeparator
	if separator == "" {
		separator = ","
	}

	for _, value := range headers.Values(h.GroupsHeader) {
		for _, group := range strings.Split(value, separator) {
			if group = strings.TrimSpace(group); group != "" {
				id.Groups = append(id.Groups, group)
			}
		}
	}

	return id, true
}
