package brokerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Session struct {
	ID            string   `json:"id"`
	Code          string   `json:"code,omitempty"`
	State         string   `json:"state"`
	SupporterName string   `json:"supporter_name,omitempty"`
	ClaimID       string   `json:"claim_id,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	HostToken     string   `json:"host_token,omitempty"`
}

type Claim struct {
	ID                  string   `json:"id"`
	State               string   `json:"state"`
	SupporterName       string   `json:"supporter_name"`
	Capabilities        []string `json:"capabilities,omitempty"`
	ClaimToken          string   `json:"claim_token,omitempty"`
	TransportDescriptor string   `json:"transport_descriptor,omitempty"`
}

type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if !strings.HasPrefix(baseURL, "http://127.0.0.1:") && !strings.HasPrefix(baseURL, "http://localhost:") && !strings.HasPrefix(baseURL, "https://") {
		return nil, errors.New("broker URL must be loopback HTTP or HTTPS")
	}
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *Client) Create(ctx context.Context, descriptor string) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions", "", map[string]any{"transport_descriptor": descriptor}, &out)
	return out, err
}

func (c *Client) Snapshot(ctx context.Context, sessionID, hostToken string) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodGet, "/v1/sessions/"+sessionID, hostToken, nil, &out)
	return out, err
}

func (c *Client) Replace(ctx context.Context, sessionID, hostToken, descriptor string) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/replace", hostToken, map[string]any{"transport_descriptor": descriptor}, &out)
	return out, err
}

func (c *Client) Approve(ctx context.Context, sessionID, hostToken, claimID string) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/approve", hostToken, map[string]any{"claim_id": claimID}, &out)
	return out, err
}

func (c *Client) Reject(ctx context.Context, sessionID, hostToken, claimID string) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/reject", hostToken, map[string]any{"claim_id": claimID}, &out)
	return out, err
}

func (c *Client) End(ctx context.Context, sessionID, hostToken string) (Session, error) {
	var out Session
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/end", hostToken, map[string]any{}, &out)
	return out, err
}

func (c *Client) Claim(ctx context.Context, code, supporterName string, capabilities []string) (Claim, error) {
	var out Claim
	err := c.do(ctx, http.MethodPost, "/v1/claims", "", map[string]any{
		"code":           code,
		"supporter_name": supporterName,
		"capabilities":   capabilities,
	}, &out)
	return out, err
}

func (c *Client) ClaimStatus(ctx context.Context, claimID, claimToken string) (Claim, error) {
	var out Claim
	err := c.do(ctx, http.MethodGet, "/v1/claims/"+claimID, claimToken, nil, &out)
	return out, err
}

func (c *Client) LeaveClaim(ctx context.Context, claimID, claimToken string) (Claim, error) {
	var out Claim
	err := c.do(ctx, http.MethodPost, "/v1/claims/"+claimID+"/leave", claimToken, map[string]any{}, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body any, out any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		var apiErr struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error.Message != "" {
			return fmt.Errorf("broker %s: %s", apiErr.Error.Code, apiErr.Error.Message)
		}
		return fmt.Errorf("broker HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
