# Cloudcode
For bug hunting tools

## Bug bounty tool

A minimal command-line scanner is available in `bug_bounty_tool.py`.

### Usage

```bash
python bug_bounty_tool.py example.com
python bug_bounty_tool.py --file targets.txt --json
```

It performs a basic target check and reports:
- HTTP status code
- Server header (if present)
- Missing common security headers
