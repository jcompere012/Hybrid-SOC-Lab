# SOC Incident Report

## SSH Brute Force Attack — ubuntu-endpoint

*Security Operations Center*

## Incident Metadata

|                           |                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **Incident ID**           | INC-2026-0012                                                                                                                        |
| **Date / Time Detected**  | 2026-03-25 09:06:49 UTC (from Wazuh alert timestamp)                                                                                 |
| **Date / Time Reported**  | 2026-03-25 09:15 UTC                                                                                                                 |
| **Analyst**               | J. Compere, SOC Analyst                                                                                                              |
| **Severity**              | High (Wazuh Rule Level 10)                                                                                                           |
| **Status**                | Closed — Remediated                                                                                                                  |
| **Classification**        | Brute Force — Credential Access                                                                                                      |
| **Affected Asset**        | ubuntu-endpoint (192.168.64.8) / hostname: soc-ubuntu                                                                                |
| **MITRE ATT\&CK**         | T1110 — Brute Force (Tactic: Credential Access)                                                                                      |
| **Compliance Frameworks** | PCI-DSS 11.4, 10.2.4, 10.2.5 | HIPAA 164.312.b | NIST SI.4, AU.14, AC.7 | GDPR IV\_35.7.d, IV\_32.2 | TSC CC6.1, CC6.8, CC7.2, CC7.3 |

## 1. Executive Summary

On March 25, 2026 at 09:06 UTC, the Wazuh SIEM detected a brute-force SSH attack targeting the ubuntu-endpoint agent (192.168.64.8). The attack consisted of rapid, automated login attempts against the username "admin" — a non-existent user on the system. Wazuh Rule 5712 fired at level 10 (High) after 8 consecutive failures exceeded the brute-force threshold. The attack originated from 127.0.0.1 (localhost), indicating the simulation was executed locally. No unauthorized access was achieved. The incident has been fully investigated and closed.

## 2. Detection

### 2.1 Initial Alert

The investigation was initiated by Wazuh alert Rule ID 5712, which triggered when the frequency threshold of 8 failed SSH authentication attempts was exceeded within the configured time window. The rule description reads:

```
sshd: brute force trying to get access to the system. Non existent user.
```

**Key detail:** The alert specifies "Non existent user," meaning the targeted account ("admin") does not exist on this system. This is significant because it indicates the attacker was guessing usernames rather than targeting a known account — a hallmark of automated, opportunistic attacks rather than targeted intrusions.

### 2.2 Alert Data (Extracted from Wazuh)

|                     |                             |                                       |
| ------------------- | --------------------------- | ------------------------------------- |
| **Field**           | **Value**                   | **Significance**                      |
| rule.id             | 5712                        | SSH brute force detection rule        |
| rule.level          | 10                          | High severity (scale 0-15)            |
| rule.mitre.id       | T1110                       | MITRE Brute Force technique           |
| rule.mitre.tactic   | Credential Access           | Attacker goal: obtain credentials     |
| rule.frequency      | 8                           | 8 failed attempts triggered the alert |
| agent.name          | ubuntu-endpoint             | Affected endpoint                     |
| agent.ip            | 192.168.64.8                | Endpoint IP address                   |
| data.srcip          | 127.0.0.1                   | Attack originated from localhost      |
| data.srcuser        | admin                       | Targeted username (non-existent)      |
| decoder.name        | sshd                        | SSH daemon decoded the events         |
| predecoder.hostname | soc-ubuntu                  | System hostname                       |
| input.type          | log                         | Collected via journald                |
| timestamp           | Mar 25, 2026 @ 09:06:49.039 | Alert fired at this time              |
| id                  | 1774444009.4381702          | Unique Wazuh event ID                 |

### 2.3 Raw Log Evidence

The full\_log field from the alert shows:

```
Mar 25 13:06:47 soc-ubuntu sshd[6274]: Failed password
for invalid user admin from 127.0.0.1 port 59188 ssh2
```

The previous\_output field reveals the cascade of failures leading up to the alert:

```
Mar 25 13:06:47 soc-ubuntu sshd[6275]: Failed password
for invalid user admin from 127.0.0.1 port 59198 ssh2
Mar 25 13:06:45 soc-ubuntu sshd[6275]: Invalid user admin
from 127.0.0.1 port 59198
Mar 25 13:06:45 soc-ubuntu sshd[6276]: Invalid user admin
from 127.0.0.1 port 59204
```

|                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ANALYST NOTE:** Notice the source ports (59188, 59198, 59204) incrementing rapidly and the timestamps clustered within 2 seconds (13:06:45 to 13:06:47). This pattern is consistent with an automated tool like Hydra using parallel threads, not manual login attempts. A human would show irregular timing and would not open multiple SSH connections simultaneously. |

## 3. Investigation & Analysis

### 3.1 Timeline Reconstruction

By examining the previous\_output field, full\_log, and alert timestamps, I reconstructed the following timeline:

|                |                                                                              |                        |
| -------------- | ---------------------------------------------------------------------------- | ---------------------- |
| **Time (UTC)** | **Event**                                                                    | **Evidence Source**    |
| 09:06:45.000   | First SSH connection attempt: "Invalid user admin from 127.0.0.1 port 59198" | previous\_output field |
| 09:06:45.000   | Second SSH connection: "Invalid user admin from 127.0.0.1 port 59204"        | previous\_output field |
| 09:06:47.000   | Password failure on port 59198: "Failed password for invalid user admin"     | previous\_output field |
| 09:06:47.000   | Password failure on port 59188: "Failed password for invalid user admin"     | full\_log field        |
| 09:06:49.039   | Wazuh Rule 5712 fires (brute force threshold of 8 exceeded)                  | Alert timestamp        |

|                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **ANALYST NOTE:** The entire attack took approximately 4 seconds (09:06:45 to 09:06:49). The frequency of 8 failures in 4 seconds confirms automated tooling. The use of parallel connections (multiple ports open simultaneously) is a signature of Hydra's -t (threads) parameter. |

### 3.2 Attacker Behavior Analysis

Based on the evidence, I assessed the following:

  - **Attack type:** Automated SSH password brute force using parallel connections

  - **Target:** Username "admin" — a non-existent account. The attacker was guessing common usernames, not targeting a known user.

  - **Source:** 127.0.0.1 (localhost). In a real-world scenario, this would be an external IP, and you would pivot to threat intelligence lookups (AbuseIPDB, VirusTotal, Shodan) to assess the source.

  - **Tool signature:** Rapid sequential port usage, parallel connections, and 2-second burst pattern are consistent with Hydra (-t 4 flag = 4 threads).

  - **Success:** None. All attempts failed because the "admin" user does not exist on this system.

### 3.3 Indicators of Compromise (IOCs)

|                 |                                            |                                              |
| --------------- | ------------------------------------------ | -------------------------------------------- |
| **IOC Type**    | **Value**                                  | **Context**                                  |
| Source IP       | 127.0.0.1                                  | Attack source (localhost in this simulation) |
| Target Username | admin                                      | Non-existent user targeted for brute force   |
| Target Service  | sshd (port 22)                             | SSH daemon on ubuntu-endpoint                |
| Tool Signature  | Parallel connections, rapid port increment | Consistent with Hydra password brute force   |
| Source Ports    | 59188, 59198, 59204 (incrementing)         | Multiple simultaneous SSH sessions           |

### 3.4 MITRE ATT\&CK Mapping

|                   |                                |           |                                                                                   |
| ----------------- | ------------------------------ | --------- | --------------------------------------------------------------------------------- |
| **Tactic**        | **Technique**                  | **ID**    | **Observed Activity**                                                             |
| Credential Access | Brute Force                    | T1110     | 8+ rapid SSH login attempts against non-existent user "admin" from automated tool |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Dictionary-based password list used against SSH service                           |

**MITRE context:** T1110 (Brute Force) falls under the Credential Access tactic. According to the MITRE ATT\&CK framework, this technique is used by threat groups including Turla (G0010), OilRig, APT28, and others. The sub-technique T1110.001 (Password Guessing) specifically covers attempts to guess passwords for existing or common usernames on a service like SSH.

### 3.5 Compliance Impact

Wazuh automatically mapped this alert to the following compliance frameworks:

|               |                            |                                                                                        |
| ------------- | -------------------------- | -------------------------------------------------------------------------------------- |
| **Framework** | **Control(s)**             | **Requirement**                                                                        |
| PCI-DSS       | 11.4, 10.2.4, 10.2.5       | Intrusion detection, invalid logical access attempts, use of identification mechanisms |
| HIPAA         | 164.312.b                  | Audit controls — mechanisms to record and examine activity in systems containing ePHI  |
| NIST 800-53   | SI.4, AU.14, AC.7          | System monitoring, session audit, unsuccessful logon attempts                          |
| GDPR          | IV\_35.7.d, IV\_32.2       | Data protection impact assessment, security of processing                              |
| TSC (SOC 2)   | CC6.1, CC6.8, CC7.2, CC7.3 | Logical access security, prevent/detect unauthorized activity, monitoring              |

## 4. Impact Assessment

  - **Unauthorized access:** None. All brute-force attempts failed. The targeted user "admin" does not exist on the system.

  - **Data exposure:** None. No session was established.

  - **Service disruption:** None. The SSH service remained operational throughout the attack.

  - **Lateral movement:** Not applicable. No foothold was gained.

  - **Systems affected:** 1 (ubuntu-endpoint / 192.168.64.8)

  - **Overall severity:** High (due to the attack vector and automation), but impact is Low (attack was unsuccessful).

## 5. Containment & Response Actions

### 5.1 Immediate Actions

1.  Verified no successful SSH logins occurred during the attack window by reviewing auth.log for "Accepted" entries

2.  Confirmed the "admin" user does not exist on the system (grep admin /etc/passwd returned no results)

3.  Reviewed active SSH sessions (who / w commands) to confirm no unauthorized sessions were active

4.  Checked for any new user accounts created during the attack window (no changes detected)

5.  Verified no authorized user credentials were compromised (all existing accounts unchanged)

### 5.2 Verification Commands Used

```
# Check for successful SSH logins during attack window
grep 'Accepted' /var/log/auth.log | grep '09:06'
# Verify 'admin' user does not exist
grep admin /etc/passwd
# Check active sessions
who
w
# Check for recently created users
grep ':0:' /etc/passwd
last -n 20
```

## 6. Recommendations

6.  **Deploy Fail2Ban:** Install and configure fail2ban on all Linux endpoints to automatically block IPs after 5 failed SSH attempts. This would have stopped this attack after the 5th failure.

7.  **Disable password authentication:** Configure SSH to accept only key-based authentication (PasswordAuthentication no in /etc/ssh/sshd\_config). This eliminates brute-force attacks entirely.

8.  **Change the default SSH port:** Move SSH from port 22 to a non-standard port to reduce automated scan noise (this is security through obscurity and should complement, not replace, other controls).

9.  **Implement rate limiting in UFW:** Add ufw limit ssh to throttle rapid connection attempts at the firewall level.

10. **Create a Wazuh active response:** Configure Wazuh to automatically block the source IP when Rule 5712 fires, providing automated containment without analyst intervention.

11. **Establish a brute-force response playbook:** Document the standard triage steps for Rule 5712 so any SOC analyst can investigate consistently.

## 7. Lessons Learned

  - **Detection worked:** Wazuh Rule 5712 correctly identified the brute-force pattern and fired at the appropriate severity. The frequency threshold of 8 was effective for this attack velocity.

  - **MITRE mapping added context:** The automatic T1110 mapping immediately categorized the attack type, which accelerated triage. The linked compliance controls (PCI-DSS, HIPAA, NIST) provide ready-made reporting for audit purposes.

  - **Raw log analysis was essential:** The previous\_output field provided the evidence needed to determine this was automated (parallel connections, 2-second window). The alert summary alone would not have revealed the tool signature.

  - **No automated response was in place:** The attack ran to completion because no active response was configured. In production, Wazuh active response or fail2ban would have blocked the source after the first few failures.

  - **Non-existent user targeting is informative:** The fact that the attacker targeted "admin" (a common default) rather than a real username indicates opportunistic scanning, not a targeted attack. This distinction affects the threat level assessment.

End of Report | Analyst: J. Compere | Date: 2026-03-25
