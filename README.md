# SOC Workspace

An AI-assisted investigation workspace for SOC analysts. Paste log lines or drop screenshots, and it
writes structured entries, builds the timeline, suggests next steps, matches indicators against OSINT,
scores the investigation's quality, and produces a report. Built for healthcare and life sciences teams,
useful for any SOC.

## Two ways to run it

| | Local (single user) | Public site (many users) |
|---|---|---|
| Turn on | default | `SOC_PUBLIC_MODE=1` (turns on by itself on Google Cloud Run and Streamlit Community Cloud) |
| AI key | `GEMINI_API_KEY` in `.env` | each analyst pastes their own key in the sidebar |
| Stored on disk | caches and a news snapshot, for speed | **nothing** |
| Send to ServiceNow, SOAR, Slack | yes, credentials in `.env` | off (credentials would have to live on the server) |
| VirusTotal / AbuseIPDB | keys in `.env` | each analyst's own keys, session memory only |

## How the public site stays stateless

- Notes, screenshots, indicators and scores live only in the analyst's session memory on the server and are
  discarded when the tab closes or refreshes. The app writes no files and no content to logs.
- Analysts keep their own work with **Save workspace** and **Load workspace** (a JSON file on their computer;
  screenshots are not included).
- The server's own environment is deliberately ignored in public mode: a `GEMINI_API_KEY`, `VT_API_KEY`,
  `SOAR_WEBHOOK_URL` or similar set on the host is never used for visitors.
- API keys are built into a client per call, never cached across sessions, and are removed from any error text.
- Uploaded workspace files, model output and RSS feed content are treated as untrusted: validated, size-capped,
  HTML-escaped, and only `http(s)` links are kept.
- Per-session limits: 60 entries, 8,000 characters per note, 4 MB per screenshot, 5 MB per upload.

**What does leave the server:** notes and screenshots go to Google's Gemini API with the analyst's own key.
Google's Gemini API terms say content sent through the free (unpaid) tier can be used to improve its products and
read by human reviewers, and that sensitive information should not be submitted there. A key with billing enabled
is a paid service. The site shows this notice to every visitor. Public IPs, domains, URLs and hashes go to
VirusTotal or AbuseIPDB only if the analyst adds their own keys. Free VirusTotal keys are for non-commercial use.

## Run locally

```
pip install -r requirements.txt
# put GEMINI_API_KEY=your_key in a file named .env
python -m streamlit run app.py
```

## Deploy option A: Streamlit Community Cloud (free, quickest)

1. Put this folder in a **public** GitHub repository. Do not commit `.env` (the included `.gitignore` excludes it).
2. Go to share.streamlit.io, choose **New app**, and select the repository, branch and `app.py`.
3. In **Advanced settings**, pick Python 3.12 and add this under **Secrets**:
   ```
   SOC_PUBLIC_MODE = "1"
   ```
4. Deploy. Your site is `https://<name>.streamlit.app`.
5. Open it and confirm you see the **Public workspace** strip at the top and an **AI access** key box in the sidebar. The app also switches public mode on by itself on Community Cloud as a safeguard, but keep the secret so it is explicit.

Good to know: about 1 GB of memory shared by all visitors, the app sleeps after 12 hours without traffic (the next
visitor wakes it in a moment), no custom domain, and limits can change at any time.

## Deploy option B: Google Cloud Run (more headroom, scales to zero)

Needs a Google Cloud project with billing enabled (a card), and the `gcloud` CLI.

```
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

gcloud run deploy soc-workspace --source . --region us-central1 --allow-unauthenticated \
  --memory 1Gi --cpu 1 --concurrency 20 --min-instances 0 --max-instances 2 \
  --timeout 3600 --session-affinity --set-env-vars SOC_PUBLIC_MODE=1
```

- `--max-instances 2` caps your worst-case bill. `--min-instances 0` means you pay nothing while nobody is using it.
- Set a **budget alert** in Billing, Budgets and alerts, so a surprise reaches you by email.
- Cloud Run's monthly free tier (request-based billing, us-central1) is 180,000 vCPU-seconds, 360,000 GiB-seconds and
  2 million requests. Beyond it, expect roughly $0.10 per instance-hour at 1 vCPU and 1 GiB. A Streamlit session holds
  a connection open, so an instance counts as active while any tab is connected, and one instance serves many analysts.
- Add a custom domain from the Cloud Run console if you want one.

## What it costs you

- AI calls: **$0**, because each analyst uses their own key.
- Hosting: $0 on Community Cloud, or a few cents to a few dollars a month on Cloud Run at modest use.
- A domain name, if you want one, is optional.

## Before you go live

- [ ] Public mode is on (you see the **Public workspace** strip).
- [ ] No secrets in the repository.
- [ ] You chose an open-source licence for the repository.
- [ ] You have read the privacy text in the app and are happy with it.
- [ ] On Cloud Run: max instances and a budget alert are set.

## Settings

| Variable | Purpose |
|---|---|
| `SOC_PUBLIC_MODE` | `1` forces public mode, `0` forces local mode |
| `GEMINI_MODEL` | model name to use (default set in `llm.py`) |
| `GEMINI_FALLBACK_MODEL` | comma-separated backup models when the main one is busy |

Local-only (ignored in public mode): `GEMINI_API_KEY`, `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SOAR_WEBHOOK_URL`,
`SOAR_WEBHOOK_TOKEN`, `SERVICENOW_INSTANCE`, `SERVICENOW_USER`, `SERVICENOW_PASSWORD`, `SERVICENOW_TABLE`,
`SLACK_WEBHOOK_URL`.

## Files

`app.py` the app · `ui.py` look and feel · `llm.py` Gemini access · `scoring.py` quality score ·
`ioc_intel.py` indicator matching · `integrations.py` ServiceNow, SOAR, Slack · `threat_intel.py` news feeds ·
`workspace_io.py` save and load · `runtime.py` mode and limits · `demo.py` sample case.

All sample data is fictional. This is a coaching and productivity aid, not a substitute for your incident
response process.
