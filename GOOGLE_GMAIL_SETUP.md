# Google Cloud / Gmail Integration Guide for TraceMail AI

This guide explains how to configure Google Cloud Platform (GCP), Google OAuth 2.0, Gmail API, and Google Cloud Pub/Sub for TraceMail AI connected-mailbox monitoring.

---

## 1. Create / Select Google Cloud Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project named `TraceMailAI` (or select an existing project).

---

## 2. Enable Gmail API
1. In GCP Console, go to **APIs & Services** &rarr; **Library**.
2. Search for **Gmail API** and click **Enable**.

---

## 3. Configure Google OAuth Consent Screen
1. Go to **APIs & Services** &rarr; **OAuth consent screen**.
2. Select User Type: **External** (for testing/developer environments) and click **Create**.
3. Fill in required App information:
   - **App name**: `TraceMail AI`
   - **User support email**: Your developer email
   - **Developer contact information**: Your developer email
4. Click **Save and Continue**.

---

## 4. Add Scopes (Minimal Permissions)
1. On the **Scopes** step, click **Add or Remove Scopes**.
2. Select the minimum read-only scope required for raw message retrieval and history delta sync:
   - `https://www.googleapis.com/auth/gmail.readonly`
3. Click **Update** &rarr; **Save and Continue**.

---

## 5. Add Test Users
1. Under **Test users**, click **Add Users**.
2. Enter your personal/test Gmail address (e.g. `your-test-account@gmail.com`).
3. Click **Save and Continue**.

---

## 6. Create OAuth 2.0 Client Credentials
1. Go to **APIs & Services** &rarr; **Credentials**.
2. Click **Create Credentials** &rarr; **OAuth client ID**.
3. Application type: **Web application**.
4. Name: `TraceMail AI Web Client`.
5. **Authorized JavaScript origins**:
   ```
   http://localhost:5173
   ```
6. **Authorized redirect URIs**:
   ```
   http://localhost:8000/api/connectors/gmail/callback
   ```
   *(Ensure the redirect URI matches exactly).*
7. Click **Create**. Copy your **Client ID** and **Client Secret**.

---

## 7. Enable & Configure Google Cloud Pub/Sub (For Push Monitoring)
1. In the GCP search bar, navigate to **Pub/Sub** &rarr; **Topics**.
2. Click **Create Topic**.
3. Topic ID: `tracemail-gmail-inbox-events`.
4. Click **Create**.
5. Grant Gmail Publish Permissions:
   - Click on your created topic &rarr; **Permissions** tab &rarr; **Add Principal**.
   - **New principal**: `gmail-api-push@system.gserviceaccount.com`
   - **Role**: `Pub/Sub Publisher`
   - Click **Save**.

---

## 8. Configure TraceMail Local Secrets File
Create the gitignored configuration file `backend/config/google_oauth.local.json`:

```json
{
  "client_id": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
  "client_secret": "YOUR_GOOGLE_CLIENT_SECRET",
  "redirect_uri": "http://localhost:8000/api/connectors/gmail/callback",
  "pubsub_topic": "projects/YOUR_GCP_PROJECT/topics/tracemail-gmail-inbox-events"
}
```

> [!CAUTION]
> Never commit `google_oauth.local.json` or client secrets to git. `backend/.gitignore` is already pre-configured to ignore all token and local credential files.

---

## 9. Local Development vs. Production Monitoring Modes

| Mode | Trigger Mechanism | Requirement | UI Indicator |
| :--- | :--- | :--- | :--- |
| **PUB/SUB PUSH** | Google Pub/Sub Webhook (`/webhook`) | Public HTTPS endpoint / GCP tunnel | `PUB/SUB PUSH` |
| **DEVELOPMENT POLLING** | Incremental `history.list` (`/poll`) | Localhost / Offline dev | `DEVELOPMENT POLLING` |

---

## 10. Connecting Gmail in TraceMail Dashboard
1. Start the TraceMail backend (`python run.py` in `backend/`) and frontend (`npm run dev` in `frontend/`).
2. In the sidebar, navigate to **Mail Connectors** (`/connections`).
3. Under the **Google Gmail** card, click **Connect Google Gmail**.
4. Log in and authorize with your Google account.
5. Once redirected back, click **Start Watch** or **Poll Ingestion Now**.
6. When new messages arrive in Gmail, TraceMail fetches raw RFC822 bytes, processes them through the forensic pipeline, and displays them on the **Live Mail Monitor** with `SOURCE: GMAIL`.
