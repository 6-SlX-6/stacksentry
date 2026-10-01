package compose

// variableExpr is an interpolation expression found in a YAML value.
type variableExpr struct {
	Name       string
	Expression string
}

// implicitVariables are always available when Compose runs: POSIX shells
// export them to child processes and Compose sets COMPOSE_PROJECT_NAME itself.
// References to them are not reported as missing.
var implicitVariables = map[string]bool{
	"COMPOSE_PROJECT_NAME": true,
	"HOME":                 true, "PWD": true, "USER": true, "LOGNAME": true, "PATH": true, "SHELL": true,
}

// findUndefaultedVariables returns interpolation expressions in s that have
// no default value, following the Compose interpolation syntax:
//
//	$$            literal dollar sign (ignored)
//	$NAME         reported
//	${NAME}       reported
//	${NAME:-def}  not reported (default); def is scanned recursively
//	${NAME-def}   not reported (default); def is scanned recursively
//	${NAME:?err}  not reported (Compose fails with an explicit error)
//	${NAME?err}   not reported (Compose fails with an explicit error)
//	${NAME:+alt}  not reported (alternative value); alt is scanned recursively
//	${NAME+alt}   not reported (alternative value); alt is scanned recursively
func findUndefaultedVariables(s string) []variableExpr {
	var out []variableExpr
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) {
			continue
		}
		next := s[i+1]
		switch {
		case next == '$':
			i++
		case next == '{':
			end := closingBrace(s, i+1)
			if end < 0 {
				return out
			}
			out = append(out, parseBraced(s[i+2:end], s[i:end+1])...)
			i = end
		case isNameStart(next):
			j := i + 1
			for j < len(s) && isNameChar(s[j]) {
				j++
			}
			out = appendVar(out, s[i+1:j], s[i:j])
			i = j - 1
		}
	}
	return out
}

func parseBraced(inner, expr string) []variableExpr {
	n := 0
	for n < len(inner) && isNameChar(inner[n]) {
		n++
	}
	if n == 0 || !isNameStart(inner[0]) {
		return nil
	}
	name, rest := inner[:n], inner[n:]
	switch {
	case rest == "":
		return appendVar(nil, name, expr)
	case hasAnyPrefix(rest, ":-", ":+"):
		return findUndefaultedVariables(rest[2:])
	case hasAnyPrefix(rest, "-", "+"):
		return findUndefaultedVariables(rest[1:])
	default:
		// ":?" / "?" make Compose fail loudly; anything else is invalid.
		return nil
	}
}

func appendVar(out []variableExpr, name, expr string) []variableExpr {
	if implicitVariables[name] {
		return out
	}
	return append(out, variableExpr{Name: name, Expression: expr})
}

// closingBrace returns the index of the brace closing the one at open,
// accounting for nested expressions such as ${A:-${B}}.
func closingBrace(s string, open int) int {
	depth := 0
	for j := open; j < len(s); j++ {
		switch s[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}
