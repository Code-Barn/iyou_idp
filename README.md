# iYou IDP

Decentralised Identity Provider — OIDC bridge with DID authentication.

---

## Mac Bridge Pathing

The Rust crypto extension lives at `src/iyou_idp/_crypto.abi3.so`.  Django
needs `src/` on `sys.path` to find it.

**`config/settings.py`** injects the path automatically:

```python
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(os.path.join(BASE_DIR, 'src'))
```

If you ever see `"Rust Crypto Bridge not found"`, re-run:

    maturin develop --manifest-path Cargo.toml

or copy the compiled `.so` from `.venv/lib/python3.*/site-packages/iyou_idp/`
into `src/iyou_idp/`.

---

## OIDC Direct-Callback (Skip Consent)

When a DID-authenticated user logs in, the normal OIDC flow would show a
consent page (`/openid/authorize/` → 200) and wait for the user to click
"Allow" before issuing an authorisation code.

The `_build_oidc_redirect()` helper in `auth_bridge/views.py` short-circuits
this: it parses the `next_url` (which carries the OIDC `client_id`,
`redirect_uri`, `state`, etc.), validates the client, creates a `Code` object
directly via `oidc_provider.lib.utils.token.create_code()`, and returns the
client's `redirect_uri?code=...&state=...` as the `redirect_url`.

**Result:** the browser goes straight from verify → WUN callback with the
auth code, skipping the consent round-trip entirely.  The same helper also
persists a `UserConsent` record so subsequent logins are equally fast.

### Test coverage

- `test_verify_redirects_directly_to_client` in `auth_bridge/tests.py`
  confirms the verify endpoint returns a client callback URI (not
  `/openid/authorize/`) when the `next_url` carries full OIDC params.
- `test_authorize_returns_code_for_authenticated_user` confirms the classic
  OIDC authorize path still works for already-logged-in users.

---

## WUN Client Settings

Register an OIDC client in the Django admin with these values:

| Field | Value |
|-------|-------|
| Client ID | `747582` |
| Redirect URIs | `http://127.0.0.1:8001/oidc/callback/` |
| Post-logout URIs | `http://127.0.0.1:8001` |
| Client type | `confidential` |
| JWT Algorithm | `RS256` |
| Response Types | `code` |
| Require Consent | ☐ (unchecked) |
| Reuse Consent | ☑ (checked) |
