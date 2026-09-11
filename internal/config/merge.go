package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// sections are the top-level keys a config file may contribute.
var sections = []string{"server", "upstreams", "fallbackUpstreams", "domains", "outputs"}

// numericPrefix matches the "10-" ordering prefix of conf.d style filenames.
var numericPrefix = regexp.MustCompile(`^[0-9]+[-_]`)

// loadDocument reads a YAML file and returns its root node, or nil when the
// file holds nothing.
func loadDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	root := unwrapDocument(&doc)
	if root == nil || root.Kind == 0 {
		return nil, nil
	}
	return root, nil
}

func unwrapDocument(node *yaml.Node) *yaml.Node {
	if node != nil && node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil
		}
		return node.Content[0]
	}
	return node
}

// resolveIncludes expands the include patterns of the main config, relative to
// its directory. Patterns are sorted so the merge order is deterministic; a
// pattern with no wildcards must match an existing file.
func resolveIncludes(configPath string, patterns []string) ([]string, error) {
	baseDir := filepath.Dir(configPath)
	var out []string
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(baseDir, pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid include pattern %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			if strings.ContainsAny(pattern, "*?[") {
				continue // an empty conf.d is not an error
			}
			return nil, fmt.Errorf("include %q not found", pattern)
		}
		sort.Strings(matches)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				return nil, err
			}
			if info.IsDir() || seen[match] {
				continue
			}
			seen[match] = true
			out = append(out, match)
		}
	}
	return out, nil
}

// sectionForFile maps a filename to the config section it carries:
// "domains.yaml", "10-domains.yaml" and "fallback_upstreams.yaml" all work.
// Only the .yaml extension is accepted.
func sectionForFile(path string) (string, bool) {
	name := filepath.Base(path)
	ext := filepath.Ext(name)
	if !strings.EqualFold(ext, ".yaml") {
		return "", false
	}
	name = strings.TrimSuffix(name, ext)
	name = numericPrefix.ReplaceAllString(name, "")
	normalized := normalizeSectionName(name)
	for _, section := range sections {
		if normalizeSectionName(section) == normalized {
			return section, true
		}
	}
	return "", false
}

func normalizeSectionName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "-", "")
	name = strings.ReplaceAll(name, "_", "")
	return name
}

// sectionDocument wraps an included file's contents under the section its
// filename names. The file holds the bare value of that section:
//
//	# domains.yaml
//	- domain: example.com
func sectionDocument(path string, root *yaml.Node) (*yaml.Node, error) {
	section, ok := sectionForFile(path)
	if !ok {
		return nil, fmt.Errorf("%s: name an included file after the section it holds (%s)",
			path, strings.Join(sections, ", "))
	}
	wrapper := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	wrapper.Content = append(wrapper.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: section},
		root,
	)
	return wrapper, nil
}

// mergeNodes merges src into dst: mappings merge key by key, sequences are
// appended, and scalars are replaced. Appending is what lets domains and
// outputs be split across several files.
func mergeNodes(dst, src *yaml.Node, path string) error {
	if dst.Kind != src.Kind {
		return fmt.Errorf("%s: cannot merge %s into %s", path, nodeKind(src), nodeKind(dst))
	}
	switch dst.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(src.Content); i += 2 {
			key, value := src.Content[i], src.Content[i+1]
			existing := mappingValue(dst, key.Value)
			if existing == nil {
				dst.Content = append(dst.Content, key, value)
				continue
			}
			if err := mergeNodes(existing, value, path); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		dst.Content = append(dst.Content, src.Content...)
	default:
		*dst = *src
	}
	return nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func nodeKind(node *yaml.Node) string {
	switch node.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		return "a scalar"
	default:
		return "an unknown node"
	}
}
