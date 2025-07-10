# ScammerDefense

Scorpion is a terminal-based multitool for gathering information and looking up potential scammers. It provides three primary functions:

1. **GeoIP Lookup** – query city, region, country and ISP for an IP address using the ipinfo.io free API.
2. **Local Device Scanner** – display basic information about the local system such as hostname, OS, CPU cores, memory, and open network connections.
3. **Reverse Phone Lookup** – use Twilio Lookup V2 API to validate phone numbers and optionally retrieve line type intelligence. Set `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` environment variables or provide them in a `.env` file.

## Requirements

- Python 3.11
- See `requirements.txt` for Python package dependencies.

## Usage

Install dependencies and run the tool:

```bash
pip install -r requirements.txt
python scorpion.py
```

Follow the on-screen menu to select a tool.
