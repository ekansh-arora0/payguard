# 🛡️ PayGuard Docker Deployment

This guide explains how to package and run the PayGuard backend using Docker. This is the easiest way to share the project with friends or deploy it to a server.

## 🚀 Getting Started

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.
- **Git LFS**: The AI model weights are large. You must have [Git LFS](https://git-lfs.github.com/) installed before cloning.

### 2. Setup
```bash
# Install Git LFS
git lfs install

# Clone the repo
git clone <your-repo-url>
cd payguard

# Pull the large model files
git lfs pull
```

### 3. Run the Backend (Docker)
Open your terminal in the root of the project and run:

```bash
docker-compose up --build
```

This will:
- Spin up a **MongoDB** database.
- Build the **PayGuard Backend** container.
- Install all dependencies (including the DIRE AI model and Tesseract OCR).
- Start the server on `http://localhost:8002`.

### 4. Run the Agent (Local)
The agent needs to run on your local machine to capture your screen and clipboard. 

**On your local machine:**
1. Install requirements:
   ```bash
   pip install -r agent/requirements.txt
   ```
2. Start the agent:
   ```bash
   python agent/agent.py
   ```

## 🖥️ Cross-Platform Support
- **Windows/macOS/Linux**: The **Backend** runs in Docker, so it works exactly the same on all systems.
- **Agent**: The agent uses `pyautogui` and `mss`, which are cross-platform. However, if your friends are on Windows/Linux, they might need to install `tkinter` or `python3-tk` for the alert popups to work correctly.

## 📂 Project Structure for Docker
- `Dockerfile`: Instructions for building the backend image.
- `docker-compose.yml`: Orchestrates the backend and database.
- `requirements.txt`: Combined Python dependencies for Backend + AI.
- `.dockerignore`: Ensures the container remains small by excluding unnecessary files.

## 🛠️ Troubleshooting
- **Port Conflict**: If port `8002` or `27017` is already in use, you can change them in `docker-compose.yml`.
- **Memory**: The AI model requires at least 2GB of RAM allocated to Docker.
