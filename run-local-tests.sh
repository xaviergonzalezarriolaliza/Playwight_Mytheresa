#!/bin/bash
set -e

cd /workspace

# Set base URL for Docker container (Jekyll serves on port 4000)
BASE=http://fashionhub-app:4000/fashionhub/

echo "Using base URL: $BASE"

# Install dependencies
npm ci

# Run challenge tests on Chromium, Firefox, WebKit
npx playwright test tests/challenge/ --project=chromium --project=firefox --project=webkit --base-url=$BASE
