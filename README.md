# ScammerDefense

Scorpion is a terminal-based multitool for gathering information and looking up potential scammers. It includes several tools:

1. **GeoIP Lookup** – query city, region, country and ISP for an IP address using the ipinfo.io free API.
2. **Local Device Scanner** – display basic information about the local system such as hostname, OS, CPU cores, memory and open network connections. Debug mode lists socket states.
3. **Reverse Phone Lookup** – use Twilio Lookup V2 API to validate phone numbers and optionally retrieve line type intelligence. Set `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` environment variables or provide them in a `.env` file.
4. **TCP Port Scanner** – scan common or full port ranges and optionally check Shodan for public results if nothing is found.
5. **WHOIS Domain Lookup** – show domain registrar and creation/expiration dates.
6. **Email Validator** – check email format and verify MX records.

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
