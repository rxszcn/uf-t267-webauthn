package protocol

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// AuthenticatorExtensionOutputs is the decoded form of the extension outputs carried in the authenticator data.
// WebAuthn Level 3 defines no authenticator extensions; every member below is defined by CTAP 2.1 or CTAP 2.2 and
// registered in the IANA "WebAuthn Extension Identifiers" registry.
//
// Specification: §6.1. Authenticator Data (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type AuthenticatorExtensionOutputs struct {
	// CredProtect is the credential protection policy applied to the credential. Registration only.
	CredProtect *CredentialProtectionPolicy `json:"credProtect,omitempty"`

	// MinPinLength is the authenticator's current minimum PIN length. Registration only.
	MinPinLength *uint `json:"minPinLength,omitempty"`

	// CredBlobSet reports whether the requested blob was stored. Registration only.
	CredBlobSet *bool `json:"-"`

	// CredBlob is the blob stored with the credential. Authentication only.
	CredBlob []byte `json:"credBlob,omitempty"`

	// HMACSecret reports whether the hmac-secret was provisioned. Registration only.
	HMACSecret *bool `json:"-"`

	// HMACSecretOutput is the encrypted hmac-secret output. Authentication only.
	HMACSecretOutput []byte `json:"-"`

	// UVM reports the user verification methods used for the operation.
	UVM []UserVerificationMethod `json:"uvm,omitempty"`

	// Extra carries authenticator extension outputs this library does not model, and the values of modelled
	// extensions that arrived with an unexpected type.
	Extra map[string]any `json:"-"`
}

// UserVerificationMethod is a single entry of the CTAP uvm extension output.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type UserVerificationMethod struct {
	UserVerificationMethod uint32 `json:"userVerificationMethod"`
	KeyProtectionType      uint32 `json:"keyProtectionType"`
	MatcherProtectionType  uint32 `json:"matcherProtectionType"`
}

// credentialProtectionPolicies maps the CTAP credProtect integer values to their policy names. The values are
// ordered by increasing strictness; see [CredentialProtectionPolicy.Value].
var credentialProtectionPolicies = map[uint64]CredentialProtectionPolicy{
	1: CredentialProtectionPolicyUserVerificationOptional,
	2: CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList,
	3: CredentialProtectionPolicyUserVerificationRequired,
}

// Value returns the CTAP credProtect integer value of this policy, reporting false for a policy this library does
// not recognise. The values increase with strictness, so an applied policy satisfies a requested one when its value
// is greater than or equal to the requested value.
//
// The lookup walks [credentialProtectionPolicies] rather than duplicating it in the opposite direction so the two
// representations cannot disagree.
func (p CredentialProtectionPolicy) Value() (value uint64, ok bool) {
	for candidate, policy := range credentialProtectionPolicies {
		if policy == p {
			return candidate, true
		}
	}

	return 0, false
}

// ParseAuthenticatorExtensionOutputs decodes the CBOR extension outputs from the authenticator data.
//
// A structurally invalid encoding is an error, as the data is signed and malformation indicates something is
// genuinely wrong. A recognised identifier carrying an unexpected type is preserved in
// [AuthenticatorExtensionOutputs.Extra] without an error, so a single non-conforming authenticator cannot fail
// every ceremony it participates in.
func ParseAuthenticatorExtensionOutputs(data []byte) (out *AuthenticatorExtensionOutputs, err error) {
	var (
		members map[string]any
		n       int
	)

	// The extension data is the remainder of the authenticator data, so the caller cannot bound it; anything after
	// the map is unaccounted for and must be rejected here or not at all.
	if n, err = webauthncbor.UnmarshalFirst(data, &members); err != nil {
		return nil, ErrBadRequest.
			WithDetails("Error decoding authenticator extension outputs").
			WithInfo(err.Error()).
			WithError(err)
	}

	if n != len(data) {
		return nil, ErrBadRequest.
			WithDetails("Leftover bytes decoding authenticator extension outputs").
			WithInfo(fmt.Sprintf("The extension output map consumed %d of %d bytes", n, len(data)))
	}

	out = &AuthenticatorExtensionOutputs{}

	// Both credProtect identifiers assign the same field, so a map carrying both would otherwise resolve by map
	// iteration order and yield a different policy from one parse to the next. ExtensionCredProtect is the
	// identifier authenticators actually echo, so it wins; the other is preserved in Extra rather than discarded,
	// leaving the conflict visible to a Relying Party which wants to inspect it.
	_, credProtect := members[ExtensionCredProtect]

	for key, value := range members {
		if key == ExtensionCredentialProtectionPolicy && credProtect {
			out.extra(key, value)

			continue
		}

		if out.assign(key, value) {
			continue
		}

		out.extra(key, value)
	}

	return out, nil
}

// extensionAuthenticatorOutputInputs maps an authenticator extension output identifier to the client extension input
// identifiers which solicit it. The two namespaces are not the same: an authenticator echoes its own abbreviated
// identifier, so 'credProtect' answers a 'credentialProtectionPolicy' input and 'hmac-secret' answers
// 'hmacCreateSecret' or 'hmacGetSecret'. Without this mapping the persisted requested list would reject a legitimate
// authenticator output merely because the input identifier the Relying Party wrote is spelt differently.
//
// An identifier absent from this map is solicited only by a requested input of the same name, which is the best
// available rule for an extension this library does not model: nothing here knows the mapping its vendor uses.
var extensionAuthenticatorOutputInputs = map[string][]string{
	ExtensionCredProtect:  {ExtensionCredentialProtectionPolicy, ExtensionEnforceCredentialProtectionPolicy},
	ExtensionMinPinLength: {ExtensionMinPinLength},
	ExtensionCredBlob:     {ExtensionCredBlob, ExtensionGetCredBlob},
	ExtensionHMACSecret:   {ExtensionHMACCreateSecret, ExtensionHMACGetSecret},
	ExtensionUVM:          {ExtensionUVM},
}

// Present returns the extension identifiers present in these authenticator extension outputs, in specification order
// followed by the sorted [AuthenticatorExtensionOutputs.Extra] keys.
//
// A modelled extension whose value arrived with an unexpected type is present through Extra rather than through its
// typed field, which is consistent with how the parser preserves it.
func (o *AuthenticatorExtensionOutputs) Present() (names []string) {
	if o == nil {
		return nil
	}

	for _, present := range []struct {
		name string
		set  bool
	}{
		{ExtensionCredProtect, o.CredProtect != nil},
		{ExtensionMinPinLength, o.MinPinLength != nil},
		{ExtensionCredBlob, o.CredBlobSet != nil || o.CredBlob != nil},
		{ExtensionHMACSecret, o.HMACSecret != nil || o.HMACSecretOutput != nil},
		{ExtensionUVM, o.UVM != nil},
	} {
		if present.set {
			names = append(names, present.name)
		}
	}

	return append(names, slices.Sorted(maps.Keys(o.Extra))...)
}

// authenticatorOutputSolicited reports whether the authenticator extension output name was requested by the Relying
// Party, as recorded in the session's requested list.
//
// The lookup goes in both directions because the two namespaces do not coincide: a modelled output identifier is
// matched against the client extension input identifiers which solicit it (see
// [extensionAuthenticatorOutputInputs]), and an identifier this library does not model is matched against a requested
// input of the same name. The latter is the only rule available for a vendor extension: nothing here knows which input
// its authenticator output answers.
func authenticatorOutputSolicited(session SessionExtensions, name string) bool {
	if inputs, ok := extensionAuthenticatorOutputInputs[name]; ok {
		for _, input := range inputs {
			if slices.Contains(session.Requested, input) {
				return true
			}
		}

		return false
	}

	return slices.Contains(session.Requested, name)
}

// extra records an extension output which was not assigned to a modelled field, allocating the map on first use.
func (o *AuthenticatorExtensionOutputs) extra(key string, value any) {
	if o.Extra == nil {
		o.Extra = map[string]any{}
	}

	o.Extra[key] = value
}

// Verify checks these authenticator extension outputs against the extensions recorded in the session.
//
// A nil receiver is valid and means the authenticator returned no extension outputs at all, which is itself a
// failure when a credential protection policy was requested with enforcement.
//
// Three rules are enforced, all of which apply only to registration. Every present output must correspond to an
// extension the Relying Party requested, exactly as [AuthenticationExtensionsClientOutputs.Verify] requires of the
// client half; the credProtect policy must be honoured when enforcement was requested; and a blob submitted for
// storage with the credential must actually have been stored. Every problem found is reported rather than only the
// first, matching [AuthenticationExtensionsClientOutputs.Verify].
//
// The unsolicited-output rule is the same §7.1 step 17 obligation the client half enforces. The authenticator data's
// extension outputs are covered by the attestation signature, so they are the stronger of the two channels to check,
// and an output accepted here is what [NewCredential] records on the credential, which is why a policy the Relying
// Party never approved must not slip through this half while the client half rejects the same identifier. The rule
// covers both modelled identifiers resolved to a typed field and unmodelled ones preserved in
// [AuthenticatorExtensionOutputs.Extra]: a vendor extension this library does not know about was equally not requested.
//
// Which requested input solicits an output is resolved by [authenticatorOutputSolicited], because the two namespaces
// are not spelled alike, and the session's requested list is the same one the client half uses, so a session persisted
// between the begin and finish steps needs no new field for this check.
//
// The applied policy is compared as at-least-as-strict rather than equal, because an authenticator is permitted to
// apply a stricter policy than the one requested, for instance where its own default exceeds the request.
//
// A ceremony which is neither [CreateCeremony] nor [AssertCeremony] is treated as a registration, matching
// [AuthenticationExtensionsClientOutputs.Verify], so an unexpected value fails closed rather than skipping the
// assertions.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func (o *AuthenticatorExtensionOutputs) Verify(session SessionExtensions, ceremony CeremonyType, policy UnsolicitedOutputPolicy) error {
	// Every rule below is a registration obligation, as is the unsolicited-output check above, so an assertion
	// ceremony has nothing here to assert.
	if ceremony == AssertCeremony {
		return nil
	}

	var errs []error

	// The guard mirrors [AuthenticationExtensionsClientOutputs.Verify]: the reject policy is the zero value, so an
	// unexpected policy value rejects rather than admits.
	if policy != UnsolicitedOutputPolicyIgnore {
		for _, name := range o.Present() {
			if !authenticatorOutputSolicited(session, name) {
				errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The authenticator returned the %q extension output which was not requested", name)))
			}
		}
	}

	if err := o.verifyCredentialProtectionPolicy(session); err != nil {
		errs = append(errs, err)
	}

	// A blob the authenticator did not store is a silent failure: the Relying Party would otherwise believe its
	// data is held against the credential and only discover otherwise when a later getCredBlob returns nothing.
	if session.CredBlob {
		if o == nil || o.CredBlobSet == nil {
			errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with a blob to store but the authenticator did not report whether it was stored", ExtensionCredBlob)))
		} else if !*o.CredBlobSet {
			errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with a blob to store but the authenticator reported it was not stored", ExtensionCredBlob)))
		}
	}

	if len(errs) == 0 {
		return nil
	}

	// As with the client extension outputs, the joined error is kept as the cause so errors.As and errors.Is reach
	// each individual problem while the caller still receives an *Error.
	joined := errors.Join(errs...)

	return ErrBadRequest.
		WithDetails(fmt.Sprintf("Error validating the authenticator extension outputs: %s", strings.ReplaceAll(joined.Error(), "\n", "; "))).
		WithError(joined)
}

// verifyCredentialProtectionPolicy asserts the policy the authenticator applied against the one the Relying Party
// required. A policy requested without enforcement is advisory, so it is not asserted.
func (o *AuthenticatorExtensionOutputs) verifyCredentialProtectionPolicy(session SessionExtensions) error {
	if !session.EnforceCredentialProtectionPolicy || session.CredentialProtectionPolicy == "" {
		return nil
	}

	requested, ok := session.CredentialProtectionPolicy.Value()
	if !ok {
		return ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with enforcement but the requested policy %q is not a known policy", ExtensionCredentialProtectionPolicy, session.CredentialProtectionPolicy))
	}

	if o == nil || o.CredProtect == nil {
		return ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with enforcement but the authenticator did not report the policy it applied", ExtensionCredentialProtectionPolicy))
	}

	// A parsed CredProtect is always one of the known policies; assign only sets it from the same map Value walks.
	applied, _ := o.CredProtect.Value()

	if applied < requested {
		return ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with enforcement of policy %q but the authenticator applied the less restrictive policy %q", ExtensionCredentialProtectionPolicy, session.CredentialProtectionPolicy, *o.CredProtect))
	}

	return nil
}

// assign stores a single decoded extension output, reporting whether the identifier was recognised and the value
// had the expected type. A false result sends the entry to Extra.
func (o *AuthenticatorExtensionOutputs) assign(key string, value any) bool {
	switch key {
	case ExtensionCredentialProtectionPolicy, ExtensionCredProtect:
		raw, ok := value.(uint64)
		if !ok {
			return false
		}

		policy, ok := credentialProtectionPolicies[raw]
		if !ok {
			return false
		}

		o.CredProtect = &policy

		return true
	case ExtensionMinPinLength:
		raw, ok := value.(uint64)
		if !ok {
			return false
		}

		if raw > math.MaxUint {
			return false
		}

		o.MinPinLength = ptr(uint(raw))

		return true
	case ExtensionCredBlob:
		switch raw := value.(type) {
		case bool:
			o.CredBlobSet = ptr(raw)
		case []byte:
			o.CredBlob = raw
		default:
			return false
		}

		return true
	case ExtensionHMACSecret:
		switch raw := value.(type) {
		case bool:
			o.HMACSecret = ptr(raw)
		case []byte:
			o.HMACSecretOutput = raw
		default:
			return false
		}

		return true
	case ExtensionUVM:
		entries, ok := value.([]any)
		if !ok {
			return false
		}

		methods := make([]UserVerificationMethod, 0, len(entries))

		for _, entry := range entries {
			fields, ok := entry.([]any)
			if !ok || len(fields) != 3 {
				return false
			}

			var method UserVerificationMethod

			for i, field := range fields {
				raw, ok := field.(uint64)
				if !ok {
					return false
				}

				if raw > math.MaxUint32 {
					return false
				}

				switch i {
				case 0:
					method.UserVerificationMethod = uint32(raw)
				case 1:
					method.KeyProtectionType = uint32(raw)
				case 2:
					method.MatcherProtectionType = uint32(raw)
				}
			}

			methods = append(methods, method)
		}

		o.UVM = methods

		return true
	default:
		return false
	}
}
