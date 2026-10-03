import asyncio
import logging
from datetime import datetime, timezone
from app.background.retrospective import ContinuousRetrospectiveScanner
from app.background.campaign_correlator import CampaignCorrelationEngine
from app.connectors.gmail import gmail_connector
from app.reporting.docx_generator import WeeklyReportGenerator
from app.database.session import SessionLocal
from app.config import settings

logger = logging.getLogger("tracemail.scheduler")

class BackgroundScheduler:
    def __init__(self):
        self.is_running = False
        self._task = None
        self._last_weekly_report_day = None

    async def _loop(self):
        logger.info("TraceMail Background Continuous Threat Intelligence Scheduler started.")
        while self.is_running:
            try:
                # 1. Continuous Retrospective IOC Rescan & Enrichment
                await ContinuousRetrospectiveScanner.run_rescan()
                
                # 2. Campaign Correlation Clustering
                CampaignCorrelationEngine.correlate_campaigns()

                # 3. Check and renew Gmail watch before expiration
                if gmail_connector.is_configured():
                    renewed = await gmail_connector.check_and_renew_watch()
                    if renewed:
                        logger.info("Gmail watch subscription auto-renewed successfully.")

                # 4. Weekly Report Generation (Runs every Sunday or once per 7-day period)
                now = datetime.now(timezone.utc)
                current_day_str = now.strftime("%Y-%W")
                if self._last_weekly_report_day != current_day_str:
                    db = SessionLocal()
                    try:
                        report_res = WeeklyReportGenerator.generate_report(db, days=7)
                        logger.info(f"Scheduled Weekly Intelligence Report generated: {report_res.get('filename')}")
                        self._last_weekly_report_day = current_day_str
                    except Exception as re:
                        logger.error(f"Weekly report automated generation failed: {re}")
                    finally:
                        db.close()

            except Exception as e:
                logger.error(f"Scheduler execution error: {str(e)}", exc_info=True)
                
            await asyncio.sleep(settings.RETROSPECTIVE_SCAN_INTERVAL_SECONDS)

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._task = asyncio.create_task(self._loop())

    def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            logger.info("Background scheduler stopped.")

scheduler = BackgroundScheduler()
