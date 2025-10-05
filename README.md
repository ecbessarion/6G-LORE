# 6G-LORE server_project

Server application for the monitoring of LoRa networks.
For the client side please refer to https://github.com/smandon/rdumtool

## Tech Stack
- Language: Python
- Package manager: pip/venv
- Docker: Yes

## Project Structure
```
└─ server/
   ├─ docker/
   │  ├─ grafana/
   │  │  └─ docker-compose.yml
   │  ├─ gui/
   │  │  └─ docker-compose.yml
   │  └─ prometheus/
   │     ├─ prometheus/
   │     └─ docker-compose.yml
   └─ GUI/
      ├─ __pycache__/
      ├─ static/
      │  └─ image.png
      ├─ templates/
      │  ├─ index.html
      │  └─ results.html
      ├─ .env
      ├─ app.py
      ├─ Dockerfile
      └─ requirements.txt
```

## Getting Started

### Prerequisites
- Python 3.10+ recommended
- Git (for version control)

### Setup & Run
1. Create and activate a virtual environment
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
Environment variables are defined in `.env`. Copy to `.env` and fill in values as needed.

### Docker
A Docker setup is included.

#### Build and run
```bash
docker build -t server_project .
docker run -p 8080:8080 server_project
```

#### Using Docker Compose
```bash
docker compose up --build
```

## Testing
For testing you will need to configure the parameters of the end-points in the env file.

## License
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.