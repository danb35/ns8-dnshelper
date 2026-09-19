// Package contract defines the JSON documents exchanged with the dnshelper
// binary: one Request on stdin, one Response on stdout.
//
// Credentials only ever travel in Request.Credentials. Nothing in a Response
// may contain them.
package contract

// Operations accepted in Request.Op.
const (
	OpListProviders = "list-providers"
	OpCapabilities  = "capabilities"
	OpValidate      = "validate"
	OpGetRecords    = "get-records"
	OpAppendRecords = "append-records"
	OpSetRecords    = "set-records"
	OpDeleteRecords = "delete-records"
	// OpListZones lists the zones the credentials can see.
	OpListZones = "list-zones"
	// OpRegistrableDomains reduces host names to the registrable domains that
	// contain them (candidate zones). It needs no provider.
	OpRegistrableDomains = "registrable-domains"
)

// Modes for OpSetRecords.
const (
	// ModeMerge keeps the existing members of each touched (name, type) RRset
	// and only replaces the ones that share their data with an input record or
	// start with one of Request.ReplacePrefixes. This is the default.
	ModeMerge = "merge"
	// ModeRRset is the raw libdns SetRecords semantics: the input records
	// become the ONLY members of each (name, type) RRset they touch.
	ModeRRset = "rrset"
)

// Error codes reported in Error.Code.
const (
	CodeInvalidRequest  = "invalid_request"
	CodeUnknownProvider = "unknown_provider"
	CodeUnsupported     = "unsupported"
	CodeConflict        = "conflict"
	CodeForbidden       = "forbidden"
	CodeZoneNotFound    = "zone_not_found"
	CodeAuthFailed      = "auth_failed"
	CodeTimeout         = "timeout"
	CodeProviderError   = "provider_error"
	CodeLocked          = "locked"
)

// Record is a DNS record as seen by API consumers. Name is relative to the
// zone ("@" for the apex). Data is the RDATA in unescaped zone-file syntax; for
// TXT it is the whole value as one unquoted string, whatever its length.
type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  int64  `json:"ttl"` // seconds; 0 lets the provider pick
	Data string `json:"data"`
}

// Filter narrows get-records. Empty fields match anything.
type Filter struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// Request is the stdin document.
type Request struct {
	Op          string            `json:"op"`
	Provider    string            `json:"provider,omitempty"`
	Zone        string            `json:"zone,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
	Records     []Record          `json:"records,omitempty"`
	Filter      *Filter           `json:"filter,omitempty"`
	DryRun      bool              `json:"dry_run,omitempty"`
	// Mode and ReplacePrefixes apply to set-records only.
	Mode            string   `json:"mode,omitempty"`
	ReplacePrefixes []string `json:"replace_prefixes,omitempty"`
	// WriteTest makes validate create and delete a throwaway TXT record.
	WriteTest bool `json:"write_test,omitempty"`
	// Names are the host names for registrable-domains.
	Names []string `json:"names,omitempty"`
}

// Candidate is a registrable domain and the host names that led to it.
type Candidate struct {
	Zone  string   `json:"zone"`
	Names []string `json:"names"`
}

// Capabilities lists which libdns interfaces the provider implements.
type Capabilities struct {
	GetRecords    bool `json:"get_records"`
	AppendRecords bool `json:"append_records"`
	SetRecords    bool `json:"set_records"`
	DeleteRecords bool `json:"delete_records"`
	ListZones     bool `json:"list_zones"`
}

// Changes is what an operation did, or with dry_run would do.
type Changes struct {
	Add    []Record `json:"add"`
	Remove []Record `json:"remove"`
}

// Validation is the result of the validate operation.
type Validation struct {
	Method    string `json:"method"`     // "list-zones" or "get-records"
	ZoneFound bool   `json:"zone_found"` // always true on success
	// WriteTest is "skipped", "passed" or "failed".
	WriteTest string `json:"write_test"`
}

// Field describes one credential field of a provider.
type Field struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
	Default  string `json:"default,omitempty"`
}

// ProviderInfo describes a supported provider for list-providers.
type ProviderInfo struct {
	Name   string   `json:"name"`
	Label  string   `json:"label"`
	Fields []Field  `json:"fields"`
	Types  []string `json:"types"` // record types the provider package is documented to handle
	Notes  string   `json:"notes,omitempty"`
}

// Error is a structured failure. Message never contains credentials.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Response is the stdout document.
type Response struct {
	OK           bool           `json:"ok"`
	Error        *Error         `json:"error,omitempty"`
	DryRun       bool           `json:"dry_run,omitempty"`
	Records      []Record       `json:"records"`
	Changes      *Changes       `json:"changes,omitempty"`
	Capabilities *Capabilities  `json:"capabilities,omitempty"`
	Validation   *Validation    `json:"validation,omitempty"`
	Providers    []ProviderInfo `json:"providers,omitempty"`
	// Zones is the result of list-zones: bare zone names, sorted.
	Zones []string `json:"zones,omitempty"`
	// Candidates is the result of registrable-domains.
	Candidates []Candidate `json:"candidates,omitempty"`
}
