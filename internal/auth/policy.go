package auth

// Policy decides what a logged-in user may do, based on group membership.
type Policy struct {
	// Access lists groups that may log in and see the hosts.
	Access []string
	// Admin lists groups that may additionally power hosts on and off. When
	// empty, everyone with access may. Admins always have access.
	Admin []string
}

// CanAccess reports whether u may use the portal at all.
func (p Policy) CanAccess(u *User) bool {
	return hasAny(u.Groups, p.Access) || hasAny(u.Groups, p.Admin)
}

// CanControl reports whether u may power a host on/off. hostGroups is the host's
// own allowed_groups; when set, it replaces the "everyone with access" default,
// and admins may still control the host.
func (p Policy) CanControl(u *User, hostGroups []string) bool {
	if !p.CanAccess(u) {
		return false
	}
	switch {
	case len(hostGroups) > 0:
		return hasAny(u.Groups, hostGroups) || hasAny(u.Groups, p.Admin)
	case len(p.Admin) > 0:
		return hasAny(u.Groups, p.Admin)
	default:
		return true
	}
}

func hasAny(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}
