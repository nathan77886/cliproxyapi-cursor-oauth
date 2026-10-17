# Upstream and protocol references

The model executor, SDK bridge integration, API-key import command, generated clients,
and existing tests originate from `auth-cursor` in:

- Repository: https://github.com/UNICKCHENG/cliproxyapi-plugins
- Commit: `178bf118211fc1b5d1a10bb449636eea65a5de49`
- License: MIT; the original copyright notice is retained in `LICENSE`.

This fork adds browser login and automatic creation of an expiring user API key.
It is an independent community plugin, not an official Cursor or CLIProxyAPI product.

Browser authentication follows the behavior of `Cursor.auth.login()` in the
official `@cursor/sdk` 1.0.38 distribution:

- https://cursor.com/docs/sdk/typescript#cursor-auth
- https://registry.npmjs.org/@cursor/sdk/-/sdk-1.0.38.tgz

The SDK uses a PKCE challenge with `/loginDeepControl`, polls `/auth/poll`, then
calls `aiserver.v1.DashboardService/CreateUserApiKey` to mint a named, expiring key.
This fork deliberately requires POST polling and refuses redirects, keeping the
single-use verifier out of query strings and access logs.

Generated protobuf descriptors retain their original upstream `go_package` option;
only local Go import paths were adapted to this repository. The inference bridge
remains pinned to upstream's checksummed `cursor/sdk-bridge` 1.0.30 release.
