# Wazuh integration

Two ways to use bluetriage with Wazuh. Both were written against the Wazuh documentation
for custom integrations and `localfile`; they have **not** been tested against a live
Wazuh manager yet, so try them on a lab manager first and please report what you find.

## 1. Enrich alerts automatically (custom integration)

Every alert at or above a level is passed to bluetriage, which looks up the IP and file
hash, posts to Discord/Slack and opens a TheHive case when the score crosses the threshold.

On the Wazuh manager:

```bash
sudo python3 -m venv /opt/bluetriage/venv
sudo /opt/bluetriage/venv/bin/pip install "git+https://github.com/your-username/Blue-Team-Triage-Tool"
sudo cp .env.example /opt/bluetriage/.env        # add VT_API_KEY, DISCORD_WEBHOOK_URL, ...
sudo chown root:wazuh /opt/bluetriage/.env && sudo chmod 640 /opt/bluetriage/.env

sudo cp integrations/wazuh/custom-bluetriage /var/ossec/integrations/
sudo chown root:wazuh /var/ossec/integrations/custom-bluetriage
sudo chmod 750 /var/ossec/integrations/custom-bluetriage
sudo install -d -o wazuh -g wazuh /var/ossec/logs/bluetriage
```

Add to `/var/ossec/etc/ossec.conf`, then `systemctl restart wazuh-manager`:

```xml
<integration>
  <name>custom-bluetriage</name>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

The script name must start with `custom-`. Paths at the top of the script
(`BLUETRIAGE_BIN`, `BLUETRIAGE_ENV`, `OUT_DIR`) can be edited. Every triaged alert is
appended to `/var/ossec/logs/bluetriage/alert_results.ndjson`; integration errors go to
`/var/ossec/logs/integrations.log`.

Keep the VirusTotal free tier in mind (4 lookups/minute, 500/day): use a high `<level>`
or a `<rule_id>` / `<group>` filter so only alerts worth a lookup are sent.

## 2. Hunt on a schedule and feed findings back into Wazuh

```cron
# /etc/cron.d/bluetriage: refresh feeds daily, hunt every 15 minutes
5 3 * * *    root  /opt/bluetriage/venv/bin/bluetriage update-feeds --feeds-dir /var/lib/bluetriage/feeds
*/15 * * * * root  /opt/bluetriage/venv/bin/bluetriage hunt /var/log/auth.log /var/log/nginx/access.log --feeds-dir /var/lib/bluetriage/feeds --out-dir /var/lib/bluetriage/latest --quiet
```

Then let the agent read `findings.ndjson` (one JSON object per finding, ECS-style):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/bluetriage/latest/findings.ndjson</location>
</localfile>
```

`findings.ndjson` is rewritten on every run, so the same finding can be ingested again.
Deduplicate in your Wazuh rule (for example with `<frequency>` / `<timeframe>`), or point
`--out-dir` at a dated directory.

> **Avoid loops:** don't ingest `alert_results.ndjson` with a rule level that triggers the
> integration again, or each enrichment result will be enriched forever.
