## wafcstrip

Strip CDN and WAF IPs from a list of IP addresses or CIDR ranges.

Built on top of the [projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) library.

## Install

```shell
go install github.com/thetowsif/wafcstrip@latest
```

## Usage

```shell
# filter out CDN/WAF IPs from a list
cat ips.txt | wafcstrip

# with concurrency
cat ips.txt | wafcstrip -c 50

# verbose output (shows vendor, type, and IP)
cat ips.txt | wafcstrip -v

# supports CIDR ranges
echo "104.16.0.0/24" | wafcstrip -v

# mixed input (IPs and CIDRs together)
cat mixed.txt | wafcstrip -v

# write CDN and non-CDN IPs to separate files
cat ips.txt | wafcstrip -cdn cdn.txt -n non-cdn.txt
```

## Detection Coverage

The modified version checks providers from two sources:

- `projectdiscovery/cdncheck` bundled provider data
- live-fetched CIDR ranges at runtime for Cloudflare, CloudFront, and Akamai

### WAF providers detected

- `cloudflare`
- `akamai`
- `incapsula`
- `imperva`
- `sucuri`

### CDN providers detected

- `cloudfront`
- `fastly`
- `google`
- `leaseweb`
- `amazon`

### Cloud providers detected by cdncheck

- `aws`
- `google`
- `oracle`

### Live range sources used by this version

- Cloudflare IPv4: `https://www.cloudflare.com/ips-v4`
- Cloudflare IPv6: `https://www.cloudflare.com/ips-v6`
- CloudFront IPv4 and IPv6: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- Akamai IPv4: `https://raw.githubusercontent.com/thetowsif/wafcstrip/refs/heads/master/WAF-List/akamai-ipv4.txt`
- Akamai IPv6: `https://raw.githubusercontent.com/thetowsif/wafcstrip/refs/heads/master/WAF-List/akamai-ipv6.txt`

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | 20 | Concurrency level |
| `-v` | false | Verbose output (`vendor,type,ip`) |
| `-cdn` | | Write CDN/WAF IPs to file |
| `-n` | | Write non-CDN IPs to file |

## Credits

Originally forked from [j3ssie/cdnstrip](https://github.com/j3ssie/cdnstrip).  
Modified by [Towsif Ibny Hassan](https://github.com/thetowsif) with CIDR support and improvements.
