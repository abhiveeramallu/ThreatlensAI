bot-detect vendor placeholder

This project integrates the detection logic from https://github.com/dobiadi/bot-detect.
Because this workspace is offline, copy the compiled bundle here:

1. Clone the repo (outside this workspace if needed):
   git clone https://github.com/dobiadi/bot-detect vendor/bot-detect
2. Build it:
   cd vendor/bot-detect
   npm install
   npm run build
3. Copy the output bundle:
   cp dist/botdetect.min.js ../../public/vendor/botdetect.min.js

The login page expects:
  public/vendor/botdetect.min.js
