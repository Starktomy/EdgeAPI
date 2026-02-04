// Package dnsla provides stub types for DNSLA API responses
package dnsla

import "errors"

// BaseResponse is the base response structure
type BaseResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *BaseResponse) Success() bool {
	return r.Code == 200 || r.Code == 0
}

func (r *BaseResponse) Error() error {
	return errors.New(r.Message)
}

// DomainListResponse represents domain list API response
type DomainListResponse struct {
	BaseResponse
	Data struct {
		Results []struct {
			Id     string `json:"id"`
			Domain string `json:"domain"`
		} `json:"results"`
	} `json:"data"`
}

// DomainResponse represents single domain API response
type DomainResponse struct {
	BaseResponse
	Data struct {
		Id string `json:"id"`
	} `json:"data"`
}

// RecordListResponse represents record list API response
type RecordListResponse struct {
	BaseResponse
	Data struct {
		Results []struct {
			Id       string `json:"id"`
			Host     string `json:"host"`
			Type     int    `json:"type"`
			Data     string `json:"data"`
			TTL      int    `json:"ttl"`
			LineCode string `json:"lineCode"`
		} `json:"results"`
	} `json:"data"`
}

// RecordCreateResponse represents record creation API response
type RecordCreateResponse struct {
	BaseResponse
	Data struct {
		Id string `json:"id"`
	} `json:"data"`
}

// RecordUpdateResponse represents record update API response
type RecordUpdateResponse struct {
	BaseResponse
}

// RecordDeleteResponse represents record deletion API response
type RecordDeleteResponse struct {
	BaseResponse
}

// AllLineListResponseChild represents a child line item
type AllLineListResponseChild struct {
	Id       string                     `json:"id"`
	Name     string                     `json:"name"`
	Code     string                     `json:"code"`
	Children []AllLineListResponseChild `json:"children"`
}

// AllLineListResponse represents line list API response
type AllLineListResponse struct {
	BaseResponse
	Data []AllLineListResponseChild `json:"data"`
}
