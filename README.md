# Peer Ride Functions
Firebase Cloud Functions for the Peer Ride web app. Handles reCAPTCHA v3 verification for critical user actions and email domain verification during user registration.

## Deployment
For remote deploy, authenticate and select your project (firebase login && firebase use <projectId>) then run `firebase deploy --only functions`. For local testing, start the Functions emulator with `firebase emulators:start --only functions` and call endpoints at http://127.0.0.1:5001/<projectId>/<region>/<functionName>. Use --project <projectId> to target different environments.