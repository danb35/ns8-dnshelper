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
	// OpApplyChanges removes Request.Remove and adds Request.Add as one
	// planned change. Every record to remove must exist, or nothing is done.
	OpApplyChanges = "apply-changes"
	// OpDiffRecords compares the zone with Request.Records (a snapshot) and
	// returns, as Changes, what apply-changes would need to remove and add to
	// make the zone equal to it. SOA and apex NS records are left out. It
	// writes nothing.
	OpDiffRecords = "diff-records"
	// OpExportZone writes the zone (or Request.Records, a snapshot, when
	// given) as a BIND-format zone file in Response.Text.
	OpExportZone = "export-zone"
	// OpParseZone reads the zone file in Request.Text into Response.Records,
	// for Request.Zone; what it leaves out is in Response.Skipped. It needs
	// no provider.
	OpParseZone = "parse-zone"
	// OpCheckPropagation asks the zone's authoritative name servers for
	// Request.Filter's name and type and compares their answers with the
	// records at the DNS host (Response.Records, Response.Servers).
	OpCheckPropagation = "check-propagation"
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
	// ModeAdd, for diff-records: only add the records the zone lacks
	// (compared without TTL), remove nothing.
	ModeAdd = "add"
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
	// CodeStale: a record apply-changes was asked to remove is not in the
	// zone (any more); the zone was changed since it was read.
	CodeStale = "stale"
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
	// Remove and Add apply to apply-changes only.
	Remove []Record `json:"remove,omitempty"`
	Add    []Record `json:"add,omitempty"`
	// WriteTest makes validate create and delete a throwaway TXT record.
	WriteTest bool `json:"write_test,omitempty"`
	// Text is the zone file for parse-zone.
	Text string `json:"text,omitempty"`
	// Names are the host names for registrable-domains.
	Names []string `json:"names,omitempty"`
}

// Skipped is a record of a zone file that parse-zone left out, and why.
type Skipped struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// ServerCheck is what one address of one authoritative name server answered.
type ServerCheck struct {
	Server  string `json:"server"`
	Address string `json:"address"`
	// Status is "same" (the values at the DNS host), "different", or "error"
	// (no answer, an error code, or not authoritative; see Message).
	Status  string   `json:"status"`
	Values  []string `json:"values"`
	Message string   `json:"message,omitempty"`
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
	// AtomicChanges: apply-changes is written in one request that the DNS
	// host applies entirely or not at all.
	AtomicChanges bool `json:"atomic_changes"`
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
	OK      bool     `json:"ok"`
	Error   *Error   `json:"error,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty"`
	Records []Record `json:"records"`
	Changes *Changes `json:"changes,omitempty"`
	// Before is the zone as read just before a write of append-records,
	// set-records, delete-records or apply-changes was attempted, whether it
	// succeeded or not. Absent when nothing was written (dry run, no change).
	Before       []Record       `json:"before,omitempty"`
	Capabilities *Capabilities  `json:"capabilities,omitempty"`
	Validation   *Validation    `json:"validation,omitempty"`
	Providers    []ProviderInfo `json:"providers,omitempty"`
	// Text is the zone file written by export-zone.
	Text string `json:"text,omitempty"`
	// Servers is the result of check-propagation, and ServersFrom where the
	// name servers were found: "dns" (the delegation) or "provider" (the
	// zone's apex NS records).
	Servers     []ServerCheck `json:"servers,omitempty"`
	ServersFrom string        `json:"servers_from,omitempty"`
	// Skipped lists what parse-zone left out.
	Skipped []Skipped `json:"skipped,omitempty"`
	// Zones is the result of list-zones: bare zone names, sorted.
	Zones []string `json:"zones,omitempty"`
	// Candidates is the result of registrable-domains.
	Candidates []Candidate `json:"candidates,omitempty"`
}
