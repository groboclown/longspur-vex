package sbommodel

import (
	"fmt"
	"sort"
	"strings"
)

type MatchableId struct {
	id     []*Identifier
	mapped map[IdentifierType]*Identifier
	key    string
}

func NewMatchableId(ids []Identifier) *MatchableId {
	// In order to make the key stable, we need to sort the identifiers.
	key := ""
	ordered := make([]*Identifier, len(ids))
	for i, id := range ids {
		ordered[i] = &id
	}
	mapped := make(map[IdentifierType]*Identifier)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Type == ordered[j].Type {
			return ordered[i].Value < ordered[j].Value
		}
		return ordered[i].Type < ordered[j].Type
	})
	for _, id := range ordered {
		key += fmt.Sprintf("%s:%s|", id.Type, id.Value)
		mapped[id.Type] = id
	}
	return &MatchableId{
		id:     ordered,
		mapped: mapped,
		key:    key,
	}
}

func (m *MatchableId) Identifiers() []*Identifier {
	ids := make([]*Identifier, len(m.id))
	copy(ids, m.id)
	return m.id
}

func (m *MatchableId) HasType(t IdentifierType) bool {
	_, exists := m.mapped[t]
	return exists
}

func (m *MatchableId) GetByType(t IdentifierType) *Identifier {
	return m.mapped[t]
}

func (m *MatchableId) Key() string {
	return m.key
}

// AsNewTypeSubset returns a new MatchableId contains exactly the types of the `m`, but with the corresponding values of the superset argument.
// If a type in `m` does not exist in the superset, the value will be empty string.
func (m *MatchableId) AsNewTypeSubset(superset []Identifier) *MatchableId {
	// The current matchable already has sorted IDs.
	// So generate the new matchable with the same order, and build up the key
	// at the same time.
	keyed := make(map[IdentifierType]*Identifier)
	for i, id := range superset {
		keyed[id.Type] = &superset[i]
	}
	mapped := make(map[IdentifierType]*Identifier)
	sub := make([]*Identifier, len(m.id))
	key := ""
	for i, id := range m.id {
		if sid, exists := keyed[id.Type]; exists {
			sub[i] = sid
			mapped[id.Type] = sid
			key += fmt.Sprintf("%s:%s|", id.Type, id.Value)
			continue
		}
		// Else, not found, so just put a placeholder with empty value.
		sid := &Identifier{
			Type:  id.Type,
			Value: "",
		}
		sub[i] = sid
		mapped[id.Type] = sid
		key += fmt.Sprintf("%s:|", id.Type)
	}
	return &MatchableId{
		id:     sub,
		mapped: mapped,
		key:    key,
	}
}

// AsSubset returns a new MatchableId contains exactly the types of the `m`, but with the corresponding values of the superset argument.
func (m *MatchableId) AsSubset(superset *MatchableId) *MatchableId {
	key := ""
	sub := make([]*Identifier, len(m.id))
	mapped := make(map[IdentifierType]*Identifier)
	for i, id := range m.id {
		if sid, exists := superset.mapped[id.Type]; exists {
			sub[i] = sid
			mapped[id.Type] = sid
			key += fmt.Sprintf("%s:%s|", id.Type, id.Value)
			continue
		}
		// Else, not found, so just put a placeholder with empty value.
		sid := &Identifier{
			Type:  id.Type,
			Value: "",
		}
		sub[i] = sid
		mapped[id.Type] = sid
		key += fmt.Sprintf("%s:|", id.Type)
	}
	return &MatchableId{
		id:     sub,
		mapped: mapped,
		key:    key,
	}
}

func (m *MatchableId) Equals(other *MatchableId) bool {
	return m.key == other.key
}

// IsSubsetEqual returns true if all identifiers in m are present in other with the same values.
// To translate - are the identifier types' values in m equal to the corresponding identifier types in other?
// If other has more identifier types than m, those are ignored.
func (m *MatchableId) IsSubsetEqual(other *MatchableId) bool {
	sub := m.AsSubset(other)
	return sub.Equals(m)
}

func (m MatchableId) String() string {
	return strings.TrimSuffix(m.key, "|")
}

// JustSbomRefs returns only the identifiers that are of type "bom-ref".
func JustSbomRefs(idents []Identifier) []Identifier {
	ret := make([]Identifier, 0, len(idents))
	for _, i := range idents {
		if i.Type == IdentifierTypeBomRef {
			ret = append(ret, i)
		}
	}
	return ret
}
