# IssSys (ALPHA STAGE)
IssSys is a small lightwave upgrade agent for your operating system.
If you don't have a package system this could help you to maintain all your systems using AI with IssAssist.

## Installation
Download the code to your machine.
Unzip IssSys to `/opt/isstech`

Go to the `/opt/isstech/IssSys` directory and run the pip install command.
`pip install -r requirements.txt`
Open the `config.json` file and modify the url path to IssAssist Host.

## Run
The software is very self maintain, but if you need any help you can always run `python3 isssys.py --help`
If you just run `python3 isssys.py` it will automatically grab the URL from the `config.json` file and connect to IssAssist.

When it talks to IssAssist it will do following steps.
- Verify if the device is registered
  - IF NO:
    - Register a user Account
    - Obtain a token and a refresh token
    - Refresh your token
    - Register your device
  - IF YES:
    - Collect Update status of your device
    - Refresh your token from IssAssist
    - Send the data to IssAssist

### Dry-run
You can run IssSys in Dry-run mode and what's happening then is that IssSys will only show Update Status that will be sent to IssAssist.

### Print Token
Do you want to collect your Refresh Token and the last used Token you can allways run the `--print-token` switch and it will print your token for reuse for Postman or any other tools that maybe necessary for testing.

## Know Issues
- At the moment we are using `keyring` to secure saving your credentials. Keyring is not working as expected for Raspberry Pi devices and this need to be solved.
- No support for `yum` distribution. But this will be fixed very soon.
- No support for `Windows Update` distribution, and this will be fixed as soon we are done with `yum`

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as per [LICENSE](https://github.com/IssTech/IssSys/blob/main/LICENSE), without any additional terms or conditions.

Contributions to this project must be accompanied by a Contributor License Agreement. We use https://cla-assistant.io to automate this process.
[![CLA assistant](https://cla-assistant.io/readme/badge/IssTech/IssSys)](https://cla-assistant.io/IssTech/IssSys)
