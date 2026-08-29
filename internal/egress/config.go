package egress

const (
	// DefaultMaxRequests is deliberately an emergency fuse rather than a tuned
	// product limit. The release corpus must record legitimate peaks before this
	// becomes a tighter default.
	DefaultMaxRequests = 100_000
	MaximumMaxRequests = 1_000_000

	defaultPromptTimeoutSeconds  = 300
	defaultMaxDestinations       = 8
	defaultMaxConnections        = 32
	defaultConnectTimeoutSeconds = 15
	defaultIdleTimeoutSeconds    = 60
	defaultMaxTransferBytes      = 8 << 30
	defaultDiskReserveBytes      = 2 << 30
)

// Config is the egress broker's policy configuration.
//
// It lives here rather than in the umbrella config type because the broker is
// the only thing that may act on it, and the layering is what makes that
// checkable: nothing below egress can read these fields at all.
type Config struct {
	// There is deliberately no auto-enable switch. Recognising cargo or go can
	// enrich a prompt; it can never create a grant, and a configuration field
	// suggesting otherwise described a capability this broker does not have.
	Mode                 string `json:"mode"`
	PromptTimeoutSeconds int    `json:"prompt_timeout_seconds"`
	GrantScope           string `json:"grant_scope"`
	MaxDestinations      int    `json:"max_destinations"`
	// MaxRequests bounds total broker work, including repeated attempts to the
	// same destination and requests rejected before a connection is opened.
	MaxRequests           int   `json:"max_requests"`
	MaxConnections        int   `json:"max_connections"`
	ConnectTimeoutSeconds int   `json:"connect_timeout_seconds"`
	IdleTimeoutSeconds    int   `json:"idle_timeout_seconds"`
	MaxTransferBytes      int64 `json:"max_transfer_bytes"`
	// DiskReserveBytes is the free space acquisition must leave on the
	// filesystem holding SRCDEST. Sources land outside the monitored worktree,
	// so the build's workspace accounting never sees them.
	DiskReserveBytes int64  `json:"disk_reserve_bytes"`
	PromptContext    string `json:"-"`
	// PromptPackage, PromptPhase and DeclaredHosts describe the request well
	// enough to answer it. "The build wants example.com:443" is not a question
	// a person can answer during a nine-package upgrade: which build, at what
	// point, and is that address anywhere in the recipe they are installing?
	//
	// Transaction data, like AllowedHosts below: never serialized, never part
	// of the policy fingerprint, and never authority - naming a host as
	// declared explains a request, it does not approve one.
	PromptPackage string   `json:"-"`
	PromptPhase   string   `json:"-"`
	DeclaredHosts []string `json:"-"`
	// PromptSources are explanation-only provenance from the frozen source plan.
	// The broker still authorizes solely by its own request and AllowedHosts;
	// these records let the trusted TTY agent explain which declared repository
	// corresponds to that request without granting it any additional authority.
	PromptSources []PromptSource `json:"-"`
	// AllowedHosts, when non-empty, is the closed set of hosts the broker may
	// contact at all. It is enforced before resolution and before any prompt.
	//
	// The verify phase sets it to the frozen VCS host set, because there it is
	// knowable: the non-VCS sources were already fetched on the trusted side, so
	// the only destination makepkg can legitimately need is a declared VCS host,
	// and asking the user about anything else trains them to approve undeclared
	// destinations. Empty means no host restriction, which is what prepare and
	// build want: a build dependency cannot be known in advance, and there the
	// prompt is the anomaly detector by design.
	//
	// Transaction data, not policy configuration, so it is not serialized and
	// does not enter the policy fingerprint.
	AllowedHosts []string `json:"-"`
}

type PromptSource struct {
	Host      string `json:"-"`
	URL       string `json:"-"`
	Kind      string `json:"-"`
	Transport string `json:"-"`
	Binding   string `json:"-"`
}

// DefaultConfig is the broker's default policy: prompt on every unrecognised
// destination, and scope any grant to this broker process. One broker exists
// for one makepkg phase; grants are never carried into a later wrapper phase.
//
// GrantScope retains its historical serialized value "transaction" for config
// compatibility. It means neither a whole yay transaction nor cross-process
// persistence. There is deliberately no host-global grant scope: an always-
// allow list is inherited by exactly the malicious update that should re-prompt.
func DefaultConfig() Config {
	return Config{
		Mode:                  "prompt",
		PromptTimeoutSeconds:  defaultPromptTimeoutSeconds,
		GrantScope:            "transaction",
		MaxDestinations:       defaultMaxDestinations,
		MaxRequests:           DefaultMaxRequests,
		MaxConnections:        defaultMaxConnections,
		ConnectTimeoutSeconds: defaultConnectTimeoutSeconds,
		IdleTimeoutSeconds:    defaultIdleTimeoutSeconds,
		MaxTransferBytes:      defaultMaxTransferBytes,
		DiskReserveBytes:      defaultDiskReserveBytes,
	}
}
