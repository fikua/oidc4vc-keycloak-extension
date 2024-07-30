<h1>OIDC4VC KeyCloak Extension for Self-Sovereign Identity Systems</h1>

# Pre-requisites
1. Docker Desktop

# Test

We add a Postman JSON file to test the OIDC4VC Keycloak extension. The file is located in the `doc` folder.

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
