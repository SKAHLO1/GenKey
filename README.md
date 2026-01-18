# GenKey Script Service

This service allows developers to extract their private key from a GenLayer keystore file securely. It is designed to run locally on your machine.

## Prerequisites

- **Node.js**: Ensure you have Node.js installed on your system. You can download it from [nodejs.org](https://nodejs.org/).
- **Keystore File**: The script expects a GenLayer keystore file located at:
  - Windows: `%USERPROFILE%\.genlayer\keystores\authenticity-gate.json`
  - Linux/Mac: `~/.genlayer/keystores/authenticity-gate.json` (Note: The script currently defaults to Windows path structure using `process.env.USERPROFILE`, ensure the path logic in the script matches your OS if not on Windows).

## Installation

1.  Open your terminal or command prompt in this directory.
2.  Install the required dependencies:

    ```bash
    npm install
    ```

## Usage

To run the script and extract your private key:

1.  Execute the start command:

    ```bash
    npm start
    ```

    Or run directly with node:

    ```bash
    node extract-private-key.js
    ```

2.  The script will attempt to locate the keystore file.
3.  When prompted, enter your **keystore password**.
4.  If successful, your private key will be displayed.

## Security Warning ⚠️

- **Keep your private key secure!** Never share it with anyone.
- This script runs locally and does not transmit your key or password over the network.
- After extracting your key (e.g., for use in a `.env` file), consider clearing your terminal history.

## Troubleshooting

- **Error: Invalid keystore format**: Ensure the file exists at the expected path and is a valid JSON keystore.
- **Error: Decryption failed**: Double-check your password.
