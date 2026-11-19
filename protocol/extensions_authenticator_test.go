package protocol

import (
	"maps"
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestCredentialProtectionPolicyValue(t *testing.T) {
	for policy, expected := range map[CredentialProtectionPolicy]uint64{
		CredentialProtectionPolicyUserVerificationOptional:                     1,
		CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList: 2,
		CredentialProtectionPolicyUserVerificationRequired:                     3,
	} {
		value, ok := policy.Value()

		assert.True(t, ok)
		assert.Equal(t, expected, value)
	}

	value, ok := CredentialProtectionPolicy("nonsense").Value()

	assert.False(t, ok)
	assert.Equal(t, uint64(0), value)
}

func TestAuthenticatorExtensionOutputsVerify(t *testing.T) {
	testCases := []struct {
		name     string
		outputs  *AuthenticatorExtensionOutputs
		session  SessionExtensions
		ceremony CeremonyType
		errs     []string
	}{
		{
			name:     "NotEnforcedIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired},
			ceremony: CreateCeremony,
		},
		{
			name:     "EnforcedWithoutPolicyIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
		},
		{
			name:     "EnforcedAndHonoured",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  SessionExtensions{Requested: []string{ExtensionCredentialProtectionPolicy}, CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
		},
		{
			// An authenticator may apply a stricter policy than the one requested, for instance where its own
			// default exceeds the request.
			name:     "EnforcedAndExceeded",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  SessionExtensions{Requested: []string{ExtensionCredentialProtectionPolicy}, CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationOptional, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
		},
		{
			name:     "EnforcedAndDowngraded",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationOptional)},
			session:  SessionExtensions{Requested: []string{ExtensionCredentialProtectionPolicy}, CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "less restrictive"},
		},
		{
			name:     "EnforcedButNotReported",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "did not report the policy"},
		},
		{
			// An authenticator returning no extension outputs at all decodes to a nil receiver.
			name:     "EnforcedWithNoOutputsAtAll",
			outputs:  nil,
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "did not report the policy"},
		},
		{
			name:     "EnforcedWithUnknownPolicy",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  SessionExtensions{Requested: []string{ExtensionCredentialProtectionPolicy}, CredentialProtectionPolicy: CredentialProtectionPolicy("nonsense"), EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "not a known policy"},
		},
		{
			// credProtect is a registration extension, so an assertion has nothing to assert.
			name:     "AssertionIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: AssertCeremony,
		},
		{
			// An unrecognised ceremony must fail closed, matching the client output guard.
			name:     "UnknownCeremonyFailsClosed",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: testCeremonyUnknown,
			errs:     []string{"credentialProtectionPolicy", "did not report the policy"},
		},
		{
			name:     "CredBlobStored",
			outputs:  &AuthenticatorExtensionOutputs{CredBlobSet: ptr(true)},
			session:  SessionExtensions{Requested: []string{ExtensionCredBlob}, CredBlob: true},
			ceremony: CreateCeremony,
		},
		{
			name:     "CredBlobNotStored",
			outputs:  &AuthenticatorExtensionOutputs{CredBlobSet: ptr(false)},
			session:  SessionExtensions{Requested: []string{ExtensionCredBlob}, CredBlob: true},
			ceremony: CreateCeremony,
			errs:     []string{"credBlob", "was not stored"},
		},
		{
			name:     "CredBlobOutcomeMissing",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{Requested: []string{ExtensionCredBlob}, CredBlob: true},
			ceremony: CreateCeremony,
			errs:     []string{"credBlob", "did not report whether it was stored"},
		},
		{
			name:     "CredBlobNotRequested",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
		},
		{
			// credBlob is a registration extension, so the authentication arm must not assert the outcome.
			name:     "CredBlobAssertionIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredBlob: true},
			ceremony: AssertCeremony,
		},
		{
			// Both rules are reported together rather than stopping at the first.
			name:     "EveryProblemIsReported",
			outputs:  &AuthenticatorExtensionOutputs{CredBlobSet: ptr(false)},
			session:  SessionExtensions{CredBlob: true, CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credBlob", "was not stored", "credentialProtectionPolicy", "did not report the policy"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.outputs.Verify(tc.session, tc.ceremony, UnsolicitedOutputPolicyReject)

			if len(tc.errs) == 0 {
				assert.NoError(t, err)

				return
			}

			for _, fragment := range tc.errs {
				assert.ErrorContains(t, err, fragment)
			}
		})
	}
}

func TestParseAuthenticatorExtensionOutputs(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{
		"credProtect":  uint64(3),
		"minPinLength": uint64(6),
		"credBlob":     true,
		"hmac-secret":  true,
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)
	require.NotNil(t, have)

	require.NotNil(t, have.CredProtect)
	assert.Equal(t, CredentialProtectionPolicyUserVerificationRequired, *have.CredProtect)

	require.NotNil(t, have.MinPinLength)
	assert.Equal(t, uint(6), *have.MinPinLength)

	require.NotNil(t, have.CredBlobSet)
	assert.True(t, *have.CredBlobSet)
	assert.Nil(t, have.CredBlob)

	require.NotNil(t, have.HMACSecret)
	assert.True(t, *have.HMACSecret)

	assert.Empty(t, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsAssertionForms(t *testing.T) {
	// credBlob and hmac-secret are polymorphic by ceremony: boolean at registration, byte string at assertion.
	data, err := webauthncbor.Marshal(map[string]any{
		"credBlob":    []byte{0x01, 0x02},
		"hmac-secret": []byte{0x03, 0x04},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, []byte{0x01, 0x02}, have.CredBlob)
	assert.Nil(t, have.CredBlobSet)
	assert.Equal(t, []byte{0x03, 0x04}, have.HMACSecretOutput)
	assert.Nil(t, have.HMACSecret)
}

func TestParseAuthenticatorExtensionOutputsUVM(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{
		"uvm": []any{
			[]any{uint64(2), uint64(4), uint64(2)},
			[]any{uint64(4), uint64(2), uint64(4)},
		},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, []UserVerificationMethod{
		{UserVerificationMethod: 2, KeyProtectionType: 4, MatcherProtectionType: 2},
		{UserVerificationMethod: 4, KeyProtectionType: 2, MatcherProtectionType: 4},
	}, have.UVM)
}

func TestParseAuthenticatorExtensionOutputsUVMMalformed(t *testing.T) {
	// A uvm output this library cannot represent is preserved in Extra rather than silently truncated, dropped, or
	// failing the whole ceremony.
	testCases := []struct {
		name  string
		value any
	}{
		{
			name:  "FieldOutOfRange",
			value: []any{[]any{uint64(math.MaxUint32) + 1, uint64(4), uint64(2)}},
		},
		{
			name:  "NotAList",
			value: "not-a-list",
		},
		{
			name:  "TooFewFields",
			value: []any{[]any{uint64(2), uint64(4)}},
		},
		{
			name:  "TooManyFields",
			value: []any{[]any{uint64(2), uint64(4), uint64(2), uint64(1)}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := webauthncbor.Marshal(map[string]any{"uvm": tc.value})
			require.NoError(t, err)

			have, err := ParseAuthenticatorExtensionOutputs(data)
			require.NoError(t, err)

			assert.Nil(t, have.UVM)
			require.Contains(t, have.Extra, "uvm")
		})
	}
}

func TestParseAuthenticatorExtensionOutputsCredProtectIdentifierPrecedence(t *testing.T) {
	// Both identifiers assign CredProtect. A map carrying both must not resolve by map iteration order, which
	// would otherwise make the policy, and therefore the enforcement check in Verify, differ between parses of
	// byte-identical signed data.
	data, err := webauthncbor.Marshal(map[string]any{
		ExtensionCredProtect:                uint64(1),
		ExtensionCredentialProtectionPolicy: uint64(3),
	})
	require.NoError(t, err)

	for range 32 {
		have, err := ParseAuthenticatorExtensionOutputs(data)
		require.NoError(t, err)

		require.NotNil(t, have.CredProtect)
		assert.Equal(t, CredentialProtectionPolicyUserVerificationOptional, *have.CredProtect,
			"the CTAP identifier authenticators echo must win")

		// The losing value stays visible rather than being silently discarded.
		assert.Equal(t, uint64(3), have.Extra[ExtensionCredentialProtectionPolicy])
	}
}

func TestParseAuthenticatorExtensionOutputsRejectsTrailingBytes(t *testing.T) {
	// The extension data is the remainder of the authenticator data, so nothing else bounds it. Anything after the
	// map is unaccounted for and must not be silently ignored.
	data, err := webauthncbor.Marshal(map[string]any{"credProtect": uint64(3)})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(append(append([]byte{}, data...), 0xff))

	assert.Nil(t, have)
	assert.ErrorContains(t, err, "Leftover bytes")

	// A second complete map is the same problem: without the length check the first would silently win.
	have, err = ParseAuthenticatorExtensionOutputs(append(append([]byte{}, data...), data...))

	assert.Nil(t, have)
	assert.ErrorContains(t, err, "Leftover bytes")
}

func TestParseAuthenticatorExtensionOutputsUnknownKey(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{"vendorThing": "x"})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"vendorThing": "x"}, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsWrongTypeIsPreserved(t *testing.T) {
	// A known key carrying an unexpected type is preserved rather than failing the ceremony, so one vendor's odd
	// encoding cannot break registration for that authenticator. Each modelled identifier has its own type
	// assertion, so each one is exercised; a branch which errored instead of falling through to Extra would fail
	// every ceremony that authenticator takes part in.
	testCases := []struct {
		name  string
		key   string
		value any
		field func(o *AuthenticatorExtensionOutputs) any
	}{
		{
			name:  "CredProtectWrongType",
			key:   ExtensionCredProtect,
			value: "three",
			field: func(o *AuthenticatorExtensionOutputs) any { return o.CredProtect },
		},
		{
			// A value outside the three policies CTAP defines is not one this library can name.
			name:  "CredProtectUnknownPolicy",
			key:   ExtensionCredProtect,
			value: uint64(4),
			field: func(o *AuthenticatorExtensionOutputs) any { return o.CredProtect },
		},
		{
			name:  "MinPinLengthWrongType",
			key:   ExtensionMinPinLength,
			value: "six",
			field: func(o *AuthenticatorExtensionOutputs) any { return o.MinPinLength },
		},
		{
			// credBlob is a bool at registration and a byte string at authentication; anything else is neither.
			name:  "CredBlobWrongType",
			key:   ExtensionCredBlob,
			value: uint64(1),
			field: func(o *AuthenticatorExtensionOutputs) any { return o.CredBlobSet },
		},
		{
			name:  "HMACSecretWrongType",
			key:   ExtensionHMACSecret,
			value: uint64(1),
			field: func(o *AuthenticatorExtensionOutputs) any { return o.HMACSecret },
		},
		{
			name:  "UVMFieldWrongType",
			key:   ExtensionUVM,
			value: []any{[]any{"not-an-integer", uint64(4), uint64(2)}},
			field: func(o *AuthenticatorExtensionOutputs) any { return o.UVM },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := webauthncbor.Marshal(map[string]any{tc.key: tc.value})
			require.NoError(t, err)

			have, err := ParseAuthenticatorExtensionOutputs(data)
			require.NoError(t, err)

			assert.Nil(t, tc.field(have), "the modelled field must stay unset")
			require.Contains(t, have.Extra, tc.key, "the value must be preserved rather than dropped")
			assert.Equal(t, tc.value, have.Extra[tc.key])
		})
	}
}

func TestParseAuthenticatorExtensionOutputsMalformed(t *testing.T) {
	// Structurally invalid CBOR is signed data that failed to parse; that is a hard error.
	_, err := ParseAuthenticatorExtensionOutputs([]byte{0xff, 0xff, 0xff})

	assert.Error(t, err)
}

// TestAuthenticatorExtensionOutputsVerifyUnsolicited covers the four-arm matrix of §7.1 step 17 on the authenticator
// side: an unrequested modelled identifier, an unrequested vendor identifier, an unrequested output under the ignore
// policy, and a requested output whose identifier is spelled differently from the input which solicited it. The
// first two arms are the split behaviour this rule closes: they were accepted end to end, and what they carried
// reached [NewCredential]'s credential record, while the client half rejected the same identifier.
//
// The requested arms are constructed through [AuthenticationExtensions.Session] wherever the wiring between input and
// output identifiers is what is under test, so a change to that mapping fails here rather than only in an end-to-end
// test that would be slower to localise.
func TestAuthenticatorExtensionOutputsVerifyUnsolicited(t *testing.T) {
	testCases := []struct {
		name     string
		outputs  *AuthenticatorExtensionOutputs
		session  SessionExtensions
		ceremony CeremonyType
		policy   UnsolicitedOutputPolicy
		errs     []string
	}{
		{
			// Arm 1: a modelled identifier the Relying Party never requested.
			name:     "UnrequestedModelled",
			outputs:  &AuthenticatorExtensionOutputs{MinPinLength: ptr(uint(6))},
			ceremony: CreateCeremony,
			errs:     []string{"minPinLength", "was not requested"},
		},
		{
			// Arm 2: a vendor identifier this library does not model, preserved in Extra by the parser. It is
			// present through Extra rather than a typed field and must be rejected on equal terms.
			name:     "UnrequestedVendor",
			outputs:  &AuthenticatorExtensionOutputs{Extra: map[string]any{"vendorThing": "x"}},
			ceremony: CreateCeremony,
			errs:     []string{"vendorThing", "was not requested"},
		},
		{
			// Arm 3: the ignore policy admits an unrequested output on this half exactly as it does on the client
			// half, so a deployment which relaxed the policy for a chatty client does not trip over its authenticator.
			name:     "UnrequestedIgnored",
			outputs:  &AuthenticatorExtensionOutputs{Extra: map[string]any{"vendorThing": "x"}},
			ceremony: CreateCeremony,
			policy:   UnsolicitedOutputPolicyIgnore,
		},
		{
			// Arm 3, modelled variant: the relaxed policy must not be selective between the two identifier kinds.
			name:     "UnrequestedModelledIgnored",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationOptional)},
			ceremony: CreateCeremony,
			policy:   UnsolicitedOutputPolicyIgnore,
		},
		{
			// Arm 4: the requested output continues to pass. The output identifier is the authenticator's own
			// 'credProtect', which the requested list records under the client input name.
			name:     "RequestedOutputPasses",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  AuthenticationExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired}.Session(),
			ceremony: CreateCeremony,
		},
		{
			// Arm 4, vendor variant: a vendor identifier is solicited by requesting the same identifier, which is
			// the only way the library can know an unmodelled output corresponds to an unmodelled input.
			name:     "RequestedVendorOutputPasses",
			outputs:  &AuthenticatorExtensionOutputs{Extra: map[string]any{"vendorThing": "x"}},
			session:  AuthenticationExtensions{Extra: map[string]any{"vendorThing": map[string]any{"ask": true}}}.Session(),
			ceremony: CreateCeremony,
		},
		{
			// Both identifiers of a modelled output are checked, and both are reported, rather than the first
			// problem hiding the second or a map's iteration order deciding which one is reported.
			name: "EveryUnrequestedOutputIsReported",
			outputs: &AuthenticatorExtensionOutputs{
				MinPinLength: ptr(uint(6)),
				Extra:        map[string]any{"vendorThing": "x"},
			},
			ceremony: CreateCeremony,
			errs:     []string{"minPinLength", "vendorThing"},
		},
		{
			// A typed field which arrived with an unexpected type lives in Extra; it is the same identifier and
			// must be judged the same way, so a wrong type is not a loophole around the unsolicited check.
			name:     "UnrequestedWrongTypedModelled",
			outputs:  &AuthenticatorExtensionOutputs{Extra: map[string]any{ExtensionCredProtect: "three"}},
			ceremony: CreateCeremony,
			errs:     []string{"credProtect", "was not requested"},
		},
		{
			// The assertion path's handling of authenticator extension outputs is deliberately unchanged: §7.2 has
			// no equivalent obligation, and the ceremony has no registration extension to assert. This arm pins
			// that the new registration check did not leak into it.
			name:     "AssertionIsUnaffected",
			outputs:  &AuthenticatorExtensionOutputs{Extra: map[string]any{"vendorThing": "x"}},
			ceremony: AssertCeremony,
			errs:     []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.outputs.Verify(tc.session, tc.ceremony, tc.policy)

			if len(tc.errs) == 0 {
				assert.NoError(t, err)

				return
			}

			for _, fragment := range tc.errs {
				assert.ErrorContains(t, err, fragment)
			}
		})
	}
}

// TestAuthenticatorExtensionOutputsVerifyUnsolicitedOutputNamesIdentifier pins that the rejection names the
// identifier the authenticator actually returned, not the input which would have solicited it. An operator reading
// the error has to correlate it with the signed authenticator data, where the abbreviated identifier appears.
func TestAuthenticatorExtensionOutputsVerifyUnsolicitedOutputNamesIdentifier(t *testing.T) {
	outputs := &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationOptional)}

	err := outputs.Verify(SessionExtensions{}, CreateCeremony, UnsolicitedOutputPolicyReject)
	require.Error(t, err)

	var protocolError *Error

	require.ErrorAs(t, err, &protocolError)
	assert.Equal(t, ErrBadRequest.Type, protocolError.Type)
	assert.Contains(t, protocolError.Details, `"credProtect"`)

	// The client half's wording is the counterpart, so a caller can distinguish which channel rejected when both
	// are checked in one ceremony.
	assert.Contains(t, protocolError.Details, "authenticator returned")
}

// TestAuthenticatorExtensionOutputsSolicitedByClientInputs covers the identifier mapping in both directions: every
// modelled authenticator output identifier is solicited by the client input(s) it answers, and no modelled output
// identifier is mapped to itself, which would be a silent no-op for an authenticator whose input name differs.
func TestAuthenticatorExtensionOutputsSolicitedByClientInputs(t *testing.T) {
	// The mapping must cover every modelled output identifier so the requested list can never cover one while the
	// check looks for the other.
	assert.ElementsMatch(t, []string{
		ExtensionCredProtect, ExtensionMinPinLength, ExtensionCredBlob, ExtensionHMACSecret, ExtensionUVM,
	}, slices.Sorted(maps.Keys(extensionAuthenticatorOutputInputs)))

	for output, inputs := range extensionAuthenticatorOutputInputs {
		for _, input := range inputs {
			assert.True(t, authenticatorOutputSolicited(SessionExtensions{Requested: []string{input}}, output),
				"requesting %q must solicit %q", input, output)
		}
	}

	// An identifier this library does not model is solicited only by the same identifier, and an unrequested one is
	// not solicited at all.
	assert.True(t, authenticatorOutputSolicited(SessionExtensions{Requested: []string{"vendorThing"}}, "vendorThing"))
	assert.False(t, authenticatorOutputSolicited(SessionExtensions{Requested: []string{"otherThing"}}, "vendorThing"))
	assert.False(t, authenticatorOutputSolicited(SessionExtensions{}, ExtensionCredProtect))
}

// TestAuthenticatorExtensionOutputsVerifyMatchesClientHalf compares the two halves of the same policy: for the same
// unrequested identifier and the same policy value, both channels must agree on whether the ceremony fails. The
// split this test pins was that the client half rejected while the authenticator half accepted, so a regression in
// either direction shows up as an asymmetry rather than only as a single failing arm.
func TestAuthenticatorExtensionOutputsVerifyMatchesClientHalf(t *testing.T) {
	// credProtect is modelled on the authenticator half; credProps is the client half's analogue. Both are
	// registration extensions which the session can record as requested.
	testCases := []struct {
		name      string
		session   SessionExtensions
		policy    UnsolicitedOutputPolicy
		wantError bool
	}{
		{
			name:      "NeitherRequestedRejectPolicy",
			policy:    UnsolicitedOutputPolicyReject,
			wantError: true,
		},
		{
			name:      "NeitherRequestedIgnorePolicy",
			policy:    UnsolicitedOutputPolicyIgnore,
			wantError: false,
		},
		{
			// Requesting the client input identifier solicits both the client output and the authenticator output
			// the input maps to, so neither half reports it.
			name:      "BothRequestedRejectPolicy",
			session:   SessionExtensions{Requested: []string{ExtensionCredProps, ExtensionCredentialProtectionPolicy}},
			policy:    UnsolicitedOutputPolicyReject,
			wantError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientErr := (AuthenticationExtensionsClientOutputs{
				CredProps: &CredentialPropertiesOutput{RK: ptr(true)},
			}).Verify(tc.session, CreateCeremony, tc.policy)

			authenticatorErr := (&AuthenticatorExtensionOutputs{
				CredProtect: ptr(CredentialProtectionPolicyUserVerificationOptional),
			}).Verify(tc.session, CreateCeremony, tc.policy)

			assert.Equal(t, tc.wantError, clientErr != nil, "client half")
			assert.Equal(t, tc.wantError, authenticatorErr != nil, "authenticator half")
		})
	}
}
