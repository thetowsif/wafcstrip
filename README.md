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
