package health

import (
	"errors"
	"regexp"
	"strings"
)

// PublicOperationPresentation is the deliberately small, safe projection of a
// Registry catalog entry that may cross into the public status surface. It is
// not a probe description: hosts, paths, keys, and request parameters stay in
// the private catalog fields.
type PublicOperationPresentation struct {
	DisplayName       string `json:"display_name"`
	GroupName         string `json:"group_name"`
	OfficialReference string `json:"official_reference"`
}

var (
	publicDatasetIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
	publicKoreanName       = regexp.MustCompile(`[가-힣]`)
)

// PublicPresentation derives display text from the catalog that LoadCatalog
// has already SHA-pinned. Missing or unsafe text is a source failure, never a
// fallback to a Gatus key or an operation identifier.
func (c CanaryConfig) PublicPresentation(canary Canary) (PublicOperationPresentation, error) {
	entry, ok := c.catalog.ByID(canary.OperationID)
	if !ok || entry.Provider != "data.go.kr" || !publicDatasetIDPattern.MatchString(entry.Aliases.DatasetID) || !validPublicDisplayName(entry.Aliases.OperationName) {
		return PublicOperationPresentation{}, errors.New("public presentation is unavailable")
	}
	return PublicOperationPresentation{
		DisplayName:       entry.Aliases.OperationName,
		GroupName:         "공공데이터",
		OfficialReference: "https://www.data.go.kr/data/" + entry.Aliases.DatasetID + "/openapi.do",
	}, nil
}

func validPublicDisplayName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len([]rune(value)) > 160 || !publicKoreanName.MatchString(value) {
		return false
	}
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"http", "://", "localhost", "127.", "apis.data.go.kr", "/", "\\"} {
		if strings.Contains(lower, forbidden) {
			return false
		}
	}
	return true
}

func validPublicPresentation(value PublicOperationPresentation) bool {
	return validPublicDisplayName(value.DisplayName) && value.GroupName == "공공데이터" && regexp.MustCompile(`^https://www\.data\.go\.kr/data/[0-9]{1,20}/openapi\.do$`).MatchString(value.OfficialReference)
}
