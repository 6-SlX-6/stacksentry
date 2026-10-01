package compose

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// rawInfo holds facts extracted from the unprocessed YAML that are lost once
// compose-go interpolates and normalizes the model.
type rawInfo struct {
	// serviceLines maps service names to the line of their definition.
	serviceLines map[string]int
	variables    []VariableRef
	hasInclude   bool
	hasVersion   bool
}

// analyzeRaw parses the YAML documents in content without interpolation.
// It rejects documents that are not YAML or whose basic shape cannot be a
// Compose file, and collects line numbers and variable references.
func analyzeRaw(display string, content []byte) (*rawInfo, error) {
	info := &rawInfo{serviceLines: map[string]int{}}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	documents := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, &LoadError{Kind: ErrInvalidYAML, Path: display, Detail: err.Error(), Err: err}
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
			continue
		}
		documents++
		if root.Kind != yaml.MappingNode {
			return nil, &LoadError{Kind: ErrUnsupported, Path: display,
				Detail: "the top-level element must be a mapping (for example \"services:\"), found " + describeKind(root)}
		}
		if err := info.inspectTop(display, root); err != nil {
			return nil, err
		}
		walkScalars(root, nil, func(path []string, node *yaml.Node) {
			for _, v := range findUndefaultedVariables(node.Value) {
				ref := VariableRef{
					Name: v.Name, Expression: v.Expression, File: display, Line: node.Line,
					Path: strings.Join(path, "."),
				}
				if len(path) > 1 && path[0] == "services" {
					ref.Service = path[1]
				}
				info.variables = append(info.variables, ref)
			}
		})
	}
	if documents == 0 {
		return nil, &LoadError{Kind: ErrNoServices, Path: display, Detail: " (the file is empty)"}
	}
	return info, nil
}

func (info *rawInfo) inspectTop(display string, root *yaml.Node) error {
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		switch key.Value {
		case "include":
			info.hasInclude = true
		case "version":
			info.hasVersion = true
		case "services":
			if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
				continue
			}
			if value.Kind != yaml.MappingNode {
				return &LoadError{Kind: ErrUnsupported, Path: display,
					Detail: "\"services\" must be a mapping of service names to service definitions, found " + describeKind(value)}
			}
			for j := 0; j+1 < len(value.Content); j += 2 {
				name := value.Content[j]
				if _, seen := info.serviceLines[name.Value]; !seen {
					info.serviceLines[name.Value] = name.Line
				}
			}
		}
	}
	return nil
}

// walkScalars visits every scalar value (not mapping keys) with its path.
// Alias nodes are skipped because the anchored node is visited where it is
// defined.
func walkScalars(node *yaml.Node, path []string, visit func([]string, *yaml.Node)) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			walkScalars(node.Content[i+1], appendPath(path, node.Content[i].Value), visit)
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			walkScalars(child, appendPath(path, strconv.Itoa(i)), visit)
		}
	case yaml.ScalarNode:
		if strings.Contains(node.Value, "$") {
			visit(path, node)
		}
	}
}

func appendPath(path []string, elem string) []string {
	out := make([]string, len(path), len(path)+1)
	copy(out, path)
	return append(out, elem)
}

func describeKind(n *yaml.Node) string {
	switch n.Kind {
	case yaml.SequenceNode:
		return "a list"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.ScalarNode:
		return "a scalar value"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "an unexpected node"
	}
}
