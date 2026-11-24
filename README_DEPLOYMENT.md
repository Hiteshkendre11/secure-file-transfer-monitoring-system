# Cloud auditor dashboard deployment

This add-on keeps the Windows monitor on Windows and deploys only the dashboard/API to Render using Docker.

## How it works

- Windows agent: runs the existing Watchdog + pywin32 monitor on a Windows endpoint.
- Event forwarding: `src/logger.py` writes events locally as before and optionally forwards event metadata over HTTPS when `MONITOR_API_URL` and `MONITOR_API_TOKEN` are set.
- Cloud API: `cloud/app.py` accepts authenticated events at `POST /api/events` and exposes a read-only dashboard and API.
- Dashboard: `/` provides Live Events and Demo Mode, the Windows agent ZIP download, GitHub source link, and health status.
- Agent download: `/download/windows-agent.zip` dynamically packages the Windows monitor, config, requirements and quick-start files. No API secret is embedded in the ZIP.

## Files added or replaced

- Add `Dockerfile`, `.dockerignore`, `render.yaml`, `cloud/`, and `windows_agent/`.
- Add `src/cloud_forwarder.py`.
- Replace `src/logger.py`, `src/integrated_monitor.py`, and `config/config.json` with the versions in this deployment pack.
- Keep the existing Windows `requirements.txt` (`watchdog`, `pywin32`). Docker installs only `cloud/requirements.txt`; it does not attempt to install Windows-only `pywin32` in Linux.

## Render setup (browser only)

1. In Render, choose **New > Web Service**, connect the GitHub repository, and select the `main` branch.
2. Choose **Docker** as the runtime. Use the repository root as the root directory and `Dockerfile` as the Dockerfile path.
3. Add environment variable `AGENT_API_TOKEN` with a long random value. Do not commit this value to GitHub. Share it with the auditor through a private channel.
4. Add `EVENT_DB_PATH=/tmp/sftms-events.sqlite3` for a free demonstration deployment.
5. Set health check path to `/health` if Render does not detect `render.yaml` automatically.
6. Deploy. The Render URL is the single entry point for the dashboard, Demo Mode, agent ZIP download, and health check.

## Windows agent setup

1. Open the dashboard URL and choose **Download Windows Agent**.
2. Extract the ZIP on the auditor's Windows computer.
3. Double-click `Run_Auditor_Agent.bat`.
4. Enter the Render URL and the API token supplied privately by the project owner.
5. Create/modify/rename harmless test files in the extracted `TransferTest` folder. Watch the dashboard's Live Events view.

## Event privacy

The Windows forwarder submits event metadata and strips directory components from source/destination paths before transmission. The cloud API stores filenames only, plus event type, severity, status, drive metadata, agent label and timestamps. File contents, hash values and full local paths are not uploaded. User and process values may be `N/A` because the current Watchdog-based event source does not attribute the originating process/user.

## Demo mode and persistence

Demo Mode uses synthetic records clearly labelled `DEMO-ONLY`; it is not evidence of live endpoint activity. Live records are kept in SQLite at `EVENT_DB_PATH`.

The included Render Blueprint uses `/tmp` for a free demonstration. Render free web services have ephemeral local storage; event history can be lost on restart, spin-down or redeploy. For persistent audit history, use a paid Render service with a persistent disk mounted at `/var/data` and set `EVENT_DB_PATH=/var/data/sftms-events.sqlite3`, or move storage to a managed database.

## Important limitations

- Cloud deployment is a dashboard and event receiver, not a remote filesystem monitor. The agent must run on a Windows endpoint to observe that endpoint's selected test folders.
- Policy checks are alert-only and do not block or quarantine file operations.
- The current configuration monitors only `TransferTest` and `Destination`.
- Copy/delete sequences across folders may arrive as separate events rather than a correlated transfer.
- Process/user attribution and arbitrary-drive monitoring are not implemented.
- Demo records are illustrative only; use Live Events for actual agent telemetry.
