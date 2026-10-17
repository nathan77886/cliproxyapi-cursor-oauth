# CLIProxyAPI Cursor Browser Login

在 CLIProxyAPI 的 OAuth 页面点击 **Cursor**，浏览器打开 Cursor 官网登录。
邮箱验证码、Google/GitHub 登录等步骤均在 Cursor 官网完成。成功后插件自动生成
90 天有效的用户 API Key，并交给 CLIProxyAPI 保存，无需手动复制 Key。

This community plugin adds Cursor browser sign-in to CLIProxyAPI while retaining
`auth-cursor` model discovery and inference through the official Cursor SDK Bridge.
It is based on [UNICKCHENG/auth-cursor](https://github.com/UNICKCHENG/cliproxyapi-plugins/tree/main/auth-cursor).
See [UPSTREAM.md](UPSTREAM.md) for the source snapshot and protocol references.

## Install

The published binary targets Linux amd64 with GLIBC 2.34 or later. Use a
plugin-capable CLIProxyAPI build. Plugin ID is `auth-cursor-oauth`; provider is
`cursor`. Do not load two Cursor plugins at the same time.

Add the registry and enable the plugin in your server configuration:

```yaml
plugins:
  enabled: true
  dir: /CLIProxyAPI/plugins # absolute path as seen inside your container
  store-sources:
    - https://raw.githubusercontent.com/nathan77886/cliproxyapi-cursor-oauth/main/registry.json
  configs:
    auth-cursor-oauth:
      enabled: true
      proxy-url: "" # set this explicitly if Cursor traffic requires a proxy
```

Reload the configuration, then install **Cursor Browser Login** from the plugin
store. Alternatively, download the Linux amd64 release archive and extract its
`auth-cursor-oauth.so` into `<plugins.dir>/linux/amd64/`, then reload or restart the server.
The release registry includes the archive SHA-256 checksum.

Keep existing plugins and their configuration. Cursor traffic uses the plugin's
`proxy-url`, not CLIProxyAPI's global proxy setting. The pinned bridge is downloaded
from GitHub Releases on first model discovery; no Node.js installation is needed.
For a persistent or offline deployment, unpack `cursor-sdk-bridge` 1.0.30 and set
`plugins.configs.auth-cursor-oauth.bridge-path` to that executable.

## Sign in

1. Refresh CLIProxyAPI's **OAuth** page and select **Cursor**.
2. Open the login link and complete authentication on `cursor.com`.
3. Keep the management page open while it polls for authorization.
4. On success, the server saves `cursor-<account>.json` in its configured auth directory.
5. Check `/v1/models` and make a request using a model available to that account.

You may use an account whose owner has authorized you to sign in; the owner can
complete email verification on the official website. Do not send passwords or
verification codes to the plugin, this repository, or an issue.

The generated key appears in the account's Cursor dashboard under a name beginning
with `CLIProxyAPI Cursor`. Account or team policies can forbid user API keys; in
that case the login reports a key-creation error and saves no credential. Keys
expire after 90 days; sign in again to renew. Revocation is available in the Cursor
dashboard. Successful re-login preserves the account's prefix, proxy, disabled flag,
and other operator settings.

## Security and behavior

- The random PKCE verifier remains server-side, with a ten-minute login lifetime.
- Polling uses POST only; credentials are never sent through redirects or URL queries.
- Concurrent polling of one login cannot mint multiple API keys.
- Temporary browser access/refresh tokens are not written to auth files or returned
  in login status; only the generated API key is persisted by CLIProxyAPI.
- Upstream error bodies are not reflected into the UI. Pending logins are bounded.
- Protect the CLIProxyAPI management API and auth directory as you would other providers.

Cursor runs use its agent SDK and the account's applicable usage pool and billing;
this is not a raw model-inference service. Model availability depends on the account.
The plugin keeps the upstream OpenAI, Claude, and Gemini compatibility behavior.

Manual key import remains available with `--cursor-login` or `--cursor-api-key`.
Prefer the management page's browser flow; command-line key arguments are visible
in process listings and shell history.

## Build and test

Requires Go 1.26 and a C compiler:

```bash
make test
cd go && go test -race ./... && go vet ./...
cd .. && make release VERSION=0.1.0
python3 scripts/smoke-host.py
```

The tests use local fake Cursor endpoints and a fake SDK bridge. They cover browser
login, pending email verification, expiration, redirects, concurrent polling,
failed key creation, credential preservation, and the existing model behavior.
A real account login and inference require interactive authorization and are
separate from these automated tests.

## License

MIT. Original author: UNICKCHENG. Browser-login additions: nathan77886.
