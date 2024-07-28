<h1>Keycloak Plugin for SSI Systems (Issuer, Wallet, Verifier)</h1>

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

# Pre-requisites
1. Docker Desktop

# Steps to run the project

1. Clone the repository
2. Create the local image of the project
    ```bash
    docker build -t oidc4vc-kc-ext .
    ```
3. Run the following command to start the Keycloak server
    ```bash
    docker compose up -d
    ```
4. Open the browser and navigate to http://localhost:8080
5. Login with the following credentials
    - Username: `admin`
    - Password: `admin`
6. When you finish, run the following command to stop the Keycloak server
    ```bash
    docker compose down
    ```

# TODO ACTIONS

- [ ] Realm implements several clients that need to be analyzed and decided which ones are necessary for the project and which ones are not.
