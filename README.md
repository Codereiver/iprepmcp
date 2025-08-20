# IPRep MCP Server

A Model Context Protocol (MCP) server that wraps the [iprep](https://github.com/Codereiver/iprep) IP and domain analysis tool, providing secure network intelligence capabilities through a Docker container.

## Features

- **IP Analysis**: Geolocation, reputation checking, and security assessment
- **Domain Analysis**: Domain reputation, DNS analysis, and content inspection
- **Dual Analysis Modes**:
  - Passive mode (default): Queries third-party APIs only
  - Active mode: Direct target infrastructure analysis
- **Batch Processing**: Analyze multiple IPs and domains simultaneously
- **Docker Deployment**: Secure, isolated container environment
- **MCP Integration**: Seamless integration with Claude and other MCP-compatible tools

## Prerequisites

- Docker installed
- Claude Desktop or another MCP-compatible client
- API keys for enhanced functionality (optional but recommended)

## Quick Start

### 1. Build the Docker Image

```bash
# Clone this repository
git clone <your-repo-url>
cd iprepmcp

# Build the Docker image (this will automatically clone the iprep repository)
docker build -t iprep-mcp .
```

### 2. Verify the Image

```bash
# Confirm the image was built successfully
docker images iprep-mcp
```

## Claude Desktop Configuration

Add the following to your Claude Desktop configuration file:

### macOS
Location: `~/Library/Application Support/Claude/claude_desktop_config.json`

### Windows
Location: `%APPDATA%\Claude\claude_desktop_config.json`

### Linux
Location: `~/.config/claude/claude_desktop_config.json`

### Configuration

```json
{
  "mcpServers": {
    "iprep": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--read-only",
        "--tmpfs=/tmp",
        "--security-opt=no-new-privileges:true",
        "iprep-mcp"
      ],
      "env": {
        "IPREP_ACTIVE_MODE": "false"
      }
    }
  }
}
```

For active mode analysis (direct target contact):

```json
{
  "mcpServers": {
    "iprep": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--read-only",
        "--tmpfs=/tmp",
        "--security-opt=no-new-privileges:true",
        "iprep-mcp"
      ],
      "env": {
        "IPREP_ACTIVE_MODE": "true"
      }
    }
  }
}
```

### Adding API Keys (Optional)

To enhance analysis capabilities, you can add API keys through environment variables in the Claude configuration:

```json
{
  "mcpServers": {
    "iprep": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--read-only",
        "--tmpfs=/tmp",
        "--security-opt=no-new-privileges:true",
        "iprep-mcp"
      ],
      "env": {
        "IPREP_ACTIVE_MODE": "false",
        "ABUSEIPDB_API_KEY": "your_key_here",
        "GREYNOISE_API_KEY": "your_key_here",
        "VIRUSTOTAL_API_KEY": "your_key_here",
        "URLVOID_API_KEY": "your_key_here",
        "IPINFO_API_KEY": "your_key_here"
      }
    }
  }
}
```

## Available Tools

Once configured, you can use these tools in Claude:

### 1. `analyze_ip`
Analyze an IP address for reputation and geolocation.

```
Example: "Analyze IP 8.8.8.8 for reputation"
```

### 2. `analyze_domain`
Analyze a domain for reputation and content.

```
Example: "Check the reputation of example.com"
```

### 3. `batch_analyze`
Analyze multiple IPs and/or domains at once.

```
Example: "Analyze these targets: 8.8.8.8, example.com, 1.1.1.1"
```

### 4. `get_analysis_config`
View current configuration and available plugins.

```
Example: "Show me the current analysis configuration"
```

## Environment Variables

Configure the server behavior through environment variables in `docker-compose.yml`:

| Variable | Description | Default |
|----------|-------------|---------|
| `IPREP_DEBUG` | Enable debug logging | `false` |
| `IPREP_ACTIVE_MODE` | Enable active analysis mode | `false` |
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |
| `RATE_LIMIT_RPM` | Requests per minute limit | `60` |

## Security Considerations

- **Passive Mode (Default)**: Only queries third-party APIs, no direct target contact
- **Active Mode**: Directly contacts target infrastructure - use responsibly
- **Container Isolation**: Runs in isolated Docker environment with security restrictions
- **Non-Root User**: Container runs as non-privileged user (UID 1000)
- **Read-Only Filesystem**: Container filesystem is mounted read-only for security
- **No Privilege Escalation**: Container cannot gain additional privileges
- **Input Validation**: All inputs are validated before processing
- **Rate Limiting**: Built-in rate limiting to prevent abuse

## API Key Services

For enhanced functionality, obtain API keys from:

- [AbuseIPDB](https://www.abuseipdb.com/api)
- [GreyNoise](https://www.greynoise.io/viz/signup)
- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [URLVoid](https://www.urlvoid.com/api/)
- [IPInfo](https://ipinfo.io/signup)

## Troubleshooting

### Container won't start
```bash
# Test the image manually
docker run --rm -i iprep-mcp

# Rebuild image
docker build --no-cache -t iprep-mcp .
```


## License

This MCP wrapper inherits the license from the original [iprep](https://github.com/Codereiver/iprep) project.


## Support

For issues with:
- MCP server wrapper: Open an issue in this repository
- iprep core functionality: See [iprep repository](https://github.com/Codereiver/iprep)