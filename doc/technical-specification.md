<h1>OIDCVC Keycloak Extension</h1>
<h2><i>Technical Specification</i></h2>

# Introduction

## keyfile.json
The `keyfile.json` is a file that contains the private key.
This file is used to sign the JWTs that are issued by the Keycloak.
The file should be placed in the root directory of the project.

## Keycloak Verifiable Credential Supported Config
The Keycloak Verifiable Credential Supported Config is described in the realm configuration.
The Keycloak client which implements that configuration is called `oidc4vci-issuer-client`.
The credential type supported establishes the format of the VC that the client can issue.

Example of the configuration:
```plaintext 
  "attributes": {
    "vctypes_LEARCredentialEmployee": "jwt_vc_json",
    "vctypes_VerifiableCertification": "jwt_vc_json",
    ...
  }
```

# Resources
