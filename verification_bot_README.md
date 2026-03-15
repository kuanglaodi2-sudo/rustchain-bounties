# Bounty Verification Bot

Automated verification system for GitHub bounty claims.

## Features

- **Star Verification**: Verify if users have starred repositories
- **Follow Verification**: Verify follow relationships
- **Wallet Validation**: Basic address format validation
- **Batch Processing**: Scan multiple claims in an issue
- **Report Generation**: Auto-generate verification reports

## Usage

```bash
# Set GitHub token
export GITHUB_TOKEN=your_token

# Scan an issue for claims
python bounty_verification_bot.py --issue 747

# Output report
python bounty_verification_bot.py --issue 747 > report.md
```

## GitHub Action

```yaml
name: Verify Bounty Claims
on:
  issue_comment:
    types: [created]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Verification
        run: python bounty_verification_bot.py --issue ${{ github.event.issue.number }}
```

## Integration

This bot integrates with the RustChain bounty system to automatically verify:
- GitHub stars
- Follow relationships  
- Wallet addresses

## License

MIT
