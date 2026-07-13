package health

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Summary is the sole public projection of a receipt.
type Summary struct {
	EndpointKey string
	Success     bool
	Duration    time.Duration
	ErrorClass  string
}

func Summarize(receipt Receipt, endpointKey string) Summary {
	return Summary{
		EndpointKey: endpointKey,
		Success:     receipt.Assessment.Outcome == "healthy",
		Duration:    time.Duration(receipt.Observation.LatencyMS) * time.Millisecond,
		ErrorClass:  receipt.Assessment.Outcome + ":" + receipt.Assessment.Category,
	}
}

type Pusher interface {
	Push(context.Context, Summary) error
}

type GatusPusher struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewGatusPusher(baseURL, token string, timeout time.Duration) *GatusPusher {
	return &GatusPusher{strings.TrimRight(baseURL, "/"), token, &http.Client{Timeout: timeout}}
}

func (p *GatusPusher) Push(ctx context.Context, summary Summary) error {
	values := url.Values{}
	values.Set("success", fmt.Sprintf("%t", summary.Success))
	values.Set("duration", summary.Duration.String())
	if !summary.Success {
		values.Set("error", summary.ErrorClass)
	}
	endpoint := p.baseURL + "/api/v1/endpoints/" + url.PathEscape(summary.EndpointKey) + "/external?" + values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Gatus returned status %d", resp.StatusCode)
	}
	return nil
}
