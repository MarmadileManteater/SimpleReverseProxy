A simple `actix-web` reverse proxy
-----------

This is a simple 🕸`actix-web` server which 🗺maps subdomains to URIs. It accepts three arguments: `path_to_cert`, `path_to_privkey`, and `path_to_map.json`. 

Here is an example JSON map which:
- Maps requests with no sub-domain to a local server at the URI `http://127.0.0.1:3000`
- Maps requests with sub-domains:
  - `astro.` to local filesystem URI `file://astro` which 👉points to `./public/astro`
  - `qwik.` to local filesystem URI `file://qwik` which 👉points to `./public/qwik`
  - `yaytapi.` to a local server at the URI `http://127.0.0.1:8080`
  
_(Note: All filesystem URIs are use the `./public` folder as the root: `file://` -> `./public/`)_

```json
{
  ".": {
    "protocol": "http",
    "uri": "127.0.0.1",
    "port": "3000"
  },
  "astro": {
    "protocol": "file",
    "uri": "astro"
  },
  "qwik": {
    "protocol": "file",
    "uri": "qwik"
  },
  "yaytapi": {
    "protocol": "http",
    "uri": "127.0.0.1",
    "port": "8080"
  }
}
```

### ⚒ Usage

```bash
./simple_rust_server path_to_cert.pem path_to_privkey.pem path_to_proxy_map.json
```

### ❗ Purpose

I started by trying to host a sveltekit server, and the solution I found for securing my server was just to use a reverse proxy, so I wrote this using [a tutorial](https://prestonfrom.com/how_to_ssl.html) and [an example](https://github.com/actix/examples/blob/master/https-tls/rustls/src/main.rs#L45) for `actix-web`. This is also partially inspired by [estk/Soxy](https://github.com/estk/soxy).
