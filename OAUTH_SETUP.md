# OAuth Hunter Setup Guide

This guide will help you set up all prerequisites for the OAuth Hunter module.

## Prerequisites Checklist

- [x] Node.js packages installed (axios, openid-client)
- [ ] Security tools installed (waybackurls, nuclei)
- [ ] Qdrant database running
- [ ] Environment variables configured

## 1. Install Security Tools

Run the installation script:

```bash
cd huntress
./scripts/install_security_tools.sh
```

This will install:
- **waybackurls**: For discovering historical OAuth endpoints
- **nuclei**: For vulnerability scanning

After installation, ensure `~/go/bin` is in your PATH:

```bash
export PATH=$PATH:~/go/bin
```

Add this to your `~/.bashrc` or `~/.zshrc` to make it permanent.

## 2. Set Up Qdrant Database

### Option A: Docker (Recommended)

```bash
cd huntress
sudo docker run -d \
  --name huntress-qdrant \
  -p 6333:6333 \
  -p 6334:6334 \
  -v $(pwd)/qdrant_storage:/qdrant/storage \
  qdrant/qdrant:latest
```

Or using Docker Compose:

```bash
sudo docker compose up -d
```

### Option B: Qdrant Cloud

1. Sign up at https://cloud.qdrant.io/
2. Create a new cluster
3. Get your API key and URL
4. Update `.env` file with cloud credentials

### Verify Qdrant is Running

```bash
curl http://localhost:6333/health
```

Should return: `{"title":"qdrant - vector search engine","version":"..."}`

## 3. Configure Environment Variables

Copy the example environment file:

```bash
cd huntress
cp config/.env.example config/.env
```

Edit `config/.env` and fill in your values:

```env
# Required
ANTHROPIC_API_KEY=sk-ant-api03-...
QDRANT_URL=http://localhost:6333

# Optional but recommended
HACKERONE_API_KEY=your_h1_api_key
HACKERONE_USERNAME=your_h1_username

# OAuth Hunter Settings
OAUTH_DISCOVERY_ENABLED=true
OAUTH_MAX_ENDPOINTS=1000
OAUTH_TIMEOUT_MS=30000

# Security Tools
WAYBACKURLS_PATH=waybackurls
NUCLEI_PATH=nuclei
```

## 4. Verify Installation

Check that all tools are available:

```bash
# Check Node packages
npm list axios openid-client

# Check security tools
which waybackurls
which nuclei

# Check Qdrant
curl http://localhost:6333/health

# Check environment
cat config/.env
```

## 5. Run OAuth Hunter

Once everything is set up:

```bash
npm run dev
```

The OAuth Hunter will be available in the Huntress interface.

## Troubleshooting

### Docker Permission Denied

If you get permission errors with Docker:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Then log out and back in.

### Go Tools Not Found

Ensure Go is installed and `~/go/bin` is in your PATH:

```bash
go version
echo $PATH | grep go/bin
```

### Qdrant Connection Failed

Check if Qdrant is running:

```bash
docker ps | grep qdrant
# or
sudo docker ps | grep qdrant
```

Restart if needed:

```bash
docker restart huntress-qdrant
# or
sudo docker restart huntress-qdrant
```

### Nuclei Templates Missing

Update nuclei templates:

```bash
nuclei -update-templates
```

## Next Steps

Once setup is complete, refer to:
- [`PIPELINE.md`](./PIPELINE.md) - Implementation roadmap
- [`OAUTH_HUNTER_ARCHITECTURE.md`](./OAUTH_HUNTER_ARCHITECTURE.md) - Technical architecture
- [`OAUTH_HUNTER_SUMMARY.md`](./OAUTH_HUNTER_SUMMARY.md) - Feature overview

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the error logs in `./logs`
3. Ensure all prerequisites are met
4. Verify environment variables are set correctly