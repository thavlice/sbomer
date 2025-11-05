# Running UI Container file for dev purposes

To run the application locally, you can use Docker Compose. Make sure you have Docker and Docker Compose installed on your machine.

1. Open a terminal and navigate to the local-dev directory (if not already there).

2. Start the services:

    ```bash
    docker-compose up --build
    ```

3. UI image is run and basic nginx config is attached, all defined in `docker-compose.yml`.
4. Access the UI at [http://localhost:8081](http://localhost:8081).
## Note
- This setup is mainly used for testing UI Containerfile related issues and changes.

- For classic UI development, running `./hack/run-local-ui.sh` from the root directory is recommended.
