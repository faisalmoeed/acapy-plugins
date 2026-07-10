# Photo ID (ISO 23220-2) Support

## Overview

Adds support for issuing Photo ID credentials (`org.iso.23220.1.mID`) as defined in ISO/IEC TS 23220-2, using the `create_and_sign_photoid` constructor in `isomdl-uniffi`.

---

## Changes

### Plugin: `oid4vc/mso_mdoc/mdoc/issuer.py`

- Added `PHOTOID_MANDATORY_FIELDS` — the 9 non-optional fields from `OrgIso232201`:
  - `family_name`, `given_name`, `birth_date`, `portrait`
  - `issue_date`, `expiry_date`, `issuing_country`
  - `issuing_authority_unicode`, `document_number`
- Added `_prepare_photoid_namespaces(payload)` — validates mandatory fields and serializes the `org.iso.23220.1` namespace as a JSON string for the Rust FFI.
- Added `elif doctype == "org.iso.23220.1.mID":` branch in `isomdl_mdoc_sign()` calling `Mdoc.create_and_sign_photoid(photoid_items, holder_jwk, cert_pem, key_pem)`.

### Demo: `oid4vc/demo/frontend/index.js`

- Added `photoIdSupportedCredCreated` and `photoIdSupportedCredID` tracking variables.
- Added `issue_photoid_credential(req, res)` — mirrors `issue_mdoc_credential` but:
  - Uses doctype `org.iso.23220.1.mID`
  - Sends ISO 23220-1 claims in the supported credential metadata
  - Omits optional fields (`sex`, `birthplace`, `height`, `weight`, etc.) from the exchange payload when blank
- Added `case "photoid":` in the POST `/issue` route switch.

### Demo: `oid4vc/demo/frontend/templates/issue-form.ejs`

- Added `<option value="photoid">Photo ID (ISO 23220-2)</option>` to the credential type selector.

### Demo: `oid4vc/demo/frontend/templates/issue/photoid.ejs` *(new)*

- Form with all ISO 23220-1 namespace fields:
  - **Mandatory**: `family_name`, `given_name`, `birth_date`, `portrait`, `issue_date`, `expiry_date`, `issuing_country`, `issuing_authority_unicode`, `document_number`
  - **Optional**: `birthplace`, `sex`, `height`, `weight`, `nationality`, `resident_address`, `resident_city`, `resident_state`, `resident_postal_code`, `resident_country`, `issuing_subdivision`, `document_type`, `age_over_18`, `age_over_21`

---

## Key Differences from mDL (ISO 18013-5)

| Field | mDL (`org.iso.18013.5.1`) | Photo ID (`org.iso.23220.1`) |
|---|---|---|
| Issuing authority | `issuing_authority` | `issuing_authority_unicode` |
| Birth location | `birth_place` | `birthplace` |
| Country codes | Alpha-2 only | Alpha-2 or Alpha-3 (`issuing_country`, `nationality`) |
| Resident country | any | Alpha-2 only |
| DL-specific fields | `driving_privileges`, `un_distinguishing_sign` | — (not present) |
| `birth_date` CBOR type | `full-date` string | Structured map (`BirthDate`) |

---

## Prerequisite: Rebuild `isomdl-uniffi`

The `create_and_sign_photoid` Rust constructor is already implemented in `isomdl-uniffi` but the auto-generated Python bindings (`isomdl_uniffi.py`) must be regenerated before the plugin code will work.

```bash
cd /Users/tim/code/timbl-ont/isomdl-uniffi
maturin develop --release
# or for a distributable wheel:
maturin build --release
pip install target/wheels/isomdl_uniffi-*.whl --force-reinstall
```

The rebuild pulls from the `feat/iso-23220-1-namespace` branch of the forked `isomdl` crate (declared in `rust/Cargo.toml`), which provides the `OrgIso232201` namespace struct and its `FromJson` / `ToNamespaceMap` implementations.

---

## Credential Subject Format

When creating an exchange record via the ACA-Py admin API, the `credential_subject` must be namespace-wrapped:

```json
{
  "org.iso.23220.1": {
    "family_name": "Doe",
    "given_name": "Jane",
    "birth_date": "1991-06-01",
    "portrait": "<base64-encoded image>",
    "issue_date": "2023-01-01",
    "expiry_date": "2033-01-01",
    "issuing_country": "CA",
    "issuing_authority_unicode": "Service Canada",
    "document_number": "ID123456789",
    "sex": 2,
    "birthplace": "Ottawa",
    "age_over_18": true,
    "age_over_21": true
  }
}
```

The `birth_date` field accepts either a plain `full-date` string (`"1991-06-01"`) or a structured map for approximate dates:

```json
"birth_date": {
  "birth_date": "1991-06-01",
  "approximate_mask": "00000000"
}
```
