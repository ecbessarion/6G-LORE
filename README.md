# server_project

Server application.

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
   - **Windows (PowerShell)**
     ```powershell
     py -3 -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **macOS/Linux**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server
   ```bash
   python server.py
   ```
   *(If your entry point is different, replace `server.py` with the correct file.)*

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


## Scripts
No scripts detected.

## API
Add your API endpoints here with examples.

## Testing
Add test instructions here.

## License
Choose a license (e.g., MIT) and add a `LICENSE` file.
