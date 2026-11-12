# Evidence

Screenshots captured while building and validating the lab.

## Phase 2 — telemetry pipeline working

Windows telemetry flowing into Elasticsearch from the monitored endpoint:

![Windows telemetry flowing into the SIEM](phase2/windows-telemetry-flowing.png)

A single Sysmon process-creation event in Discover — full command line, parent process, and file hashes (the depth native Windows logging doesn't provide):

![Sysmon process event detail](phase2/discover-sysmon-process.png)

## Phase 3 — detections firing

Alerts raised by the detection rules on the monitored host:

![Detections firing in Elastic Security](phase3/alerts-firing.png)

An alert opened for triage — rule context, the user and host entities, and the MITRE ATT&CK mapping (Execution → T1059.001):

![Alert triage with MITRE ATT&CK mapping](phase3/alert-triage-mitre.png)
