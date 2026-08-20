### `Overview`

- Run it, scan the QR code from a phone or point a browser at the printed URL, enter the PIN, and you have two-way file transfer between every device on that WiFi.
- A heuristic threat-scoring layer; A middleware runs on every request before it reaches any route handler.
- It scores the request path, query string, and, on state-changing methods, the origin header against a small set of patterns.
- Cross a threshold and the source address gets a temporary block, 30 minutes by default, logged as a security event and visible in the desktop panel's Security tab.

  <img width="777" height="542" alt="Lumenfrontend01" src="https://github.com/user-attachments/assets/95a82c57-7597-47b2-8432-eae60fd8a3f4" />

  <img width="797" height="1280" alt="LumenfrontenMobile" src="https://github.com/user-attachments/assets/be460580-0859-43ab-8d20-bcef92eade60" />

### `Installing and run`

        pip install fastapi uvicorn python-multipart qrcode pillow itsdangerous ttkbootstrap
      
        python lumendrop.py ~/Shared --port 8420

- The folder argument is optional (~/LumenDrop by default) and gets created if it doesn't exist. 
- For a headless box, a server, a Raspberry Pi, anything without a display, run:

        python lumendrop.py ~/Shared --port 8420 --no-gui

- This prints the URL and PIN straight to the terminal and runs until you Ctrl+C it.
- If you're running this somewhere you're already root or an administrator, for example inside a container, you'll need --allow-root.
- See the privilege check note below for why that flag exists.

### `Disclaimer`

- This tool is under development and is being provided on an "as-is" basis and some limitations were validated during the tests. For example:
- The quarantine heuristics are signature-based.
- Single shared folder, single server process. This isn't built for scale. It's built for a room full of devices on the same WiFi.
  
- These and other improvements will be implemented; feel free to contribute, and if you find any bugs or vulnerabilities, please open an issue.
