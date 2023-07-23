# local-jwks-server

[![CI](https://github.com/murar8/local-jwks-server/actions/workflows/ci.yml/badge.svg)](https://github.com/murar8/local-jwks-server/actions/workflows/ci.yml)

This project provides a local server that can be used to serve a JSON Web Key Set endpoint for testing purposes. It can be used to test applications that rely on a JWKS endpoint for authentication, for example for mocking the auth0 signature verification.

## Running the server

The server can be run using docker:

```bash
docker run --rm -d -p 8080:8080 ghcr.io/murar8/local-jwks-server:latest
```

Docker compose can also be used:

```yaml
services:
    local-jwks-server:
        image: ghcr.io/murar8/local-jwks-server:latest

    my-app:
        build: .
        environment:
            JWKS_ENDPOINT: http://local-jwks-server:8080/.well-known/jwks.json
        depends_on:
            local-jwks-server:
                condition: service_healthy
```

The server will generate a random key based on the provided configuration.

## Usage

### Retrieving the JSON Web Key Set

The server exposes a JWKS endpoint at `/.well-known/jwks.json` that can be used to retrieve a JSON Web Key Set.

#### Example:

```bash
curl http://localhost:8080/.well-known/jwks.json
```

```json
{
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "key_ops": null,
            "kid": "IEff3BluQ9g1FfhnXfnemjW_7nfUBwV-eZdoXPdUjeg",
            "kty": "RSA",
            "n": "v2quwe3LT7bdgtbk0VThV-XUcs0qEeyYqz_CzfHDQLICf7wv-mAyOm3P6QFxKRF35n0Qx5iPjliiw6cOXpMVYHONI_IcTeGunhqx2OTQhNgPOmQytPtaiIRlG5Gu8-y79Gy4rDqt2OSxOAoBMvxlJcBM9wKy8wbeyW8Gkdtpu_fIvJZlgygazzKOQ4gI8roPpxOj5hjupsGjlYWsdAiPUAZxru0aOeBIl2b9qVxTyWLysGkf5XSR03jS3dMD3x1D10uOpAJYqTIw0FXTJTtTf5klAxaD1RNRgqovAd1TOtB-WEwgLH8dkZTC1z7jdccYK1XuRLSFE8YBcJA3gsvIGw",
            "use": "sig"
        }
    ]
}
```

### Generate a signed JWT for testing

The server exposes a `/jwt/sign` endpoint that can be used to generate a signed JWT for testing purposes. This is useful during development and testing to generate a JWT that can be used to authenticate requests. You must provide the JWT payload as a JSON object in the request body.

#### Example:

```bash
curl -X POST -H "Content-Type: application/json" -d '{ "sub": "lnzmrr@gmail.com" }' http://localhost:8080/jwt/sign
```

```json
{
    "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6IklFZmYzQmx1UTlnMUZmaG5YZm5lbWpXXzduZlVCd1YtZVpkb1hQZFVqZWciLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJsbnptcnJAZ21haWwuY29tIn0.A0PO4Qbf4AeDMrboOX3rUK17Un3SEIqT10T6Ejky4Y_LxmQMpV8R75wLX52EI67KenLIScncysh5gWkPiXFm3y6XMp3y9HFgWykDuR7pJJ-zbdbqRQ5qxOgms7rKw2y4hjpncyQuoL3z7Gm2GhqSmLXrrARB3J2DnDZdXWlDIMxDA-buLP8Ift06PuIAb8s1qozcouHLNOUNBYyzwPeRiQ4QtUAwl5ewFwAyTlssLMwDvlV3lWMPTWY5bfpfUeYah8zVY7gD_lM5Vi2mPCL89PImSIjH10yRrckNXnDa8Paqp5DuEL8mJ0KBpUF0FRTEdBoO3LPs1OwAkRdzavZ7lQ"
}
```

## Configuration

All configuration is managed via environment variables:

| Name        | Description                               | Default |
| ----------- | ----------------------------------------- | ------- |
| JWK_USE     | RFC7517 Public Key Use.                   | sig     |
| JWK_ALG     | RFC7518 JWS Algorithm.                    | RS256   |
| JWK_KEY_OPS | RFC7517 Key Operations (comma separated). | -       |
| SERVER_ADDR | Server listening address.                 | 0.0.0.0 |
| SERVER_PORT | Server listening port.                    | 8080    |

## Contributing

The repository comes with a preconfigured development container for VSCode. To use it, simply open the repository in VSCode and click the "Reopen in Container" button.

### Starting a development server

```bash
go run github.com/cosmtrek/air
```

### Running the unit test suite

The unit test suite does not require any external dependencies and can be run without docker.

```bash
go test ./...
```

### Running the e2e test suite

The e2e test suite requires docker and docker compose to be installed.

```bash
docker compose run --rm --build test
```

## License

MIT License

Copyright (c) 2023 Lorenzo Murarotto <lnzmrr@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
