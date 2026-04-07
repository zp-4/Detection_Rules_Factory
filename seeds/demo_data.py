"""Demo data seeds."""
from sqlalchemy.orm import Session
from db.session import SessionLocal
from db.repo import UseCaseRepository, RuleRepository
from utils.hashing import compute_rule_hash


def seed_demo_data():
    """Seed demo use cases and rules."""
    db = SessionLocal()
    
    try:
        # Use Case 1: PowerShell Webhook Detection
        uc1 = UseCaseRepository.create(
            db,
            name="PowerShell Webhook Exfiltration Detection",
            description="Detect PowerShell processes making webhook connections for data exfiltration",
            objective="Detect T1567.004 - Exfiltration Over Webhook",
            status="approved",
            technologies=["Windows", "PowerShell"],
            log_sources=["Windows Event Logs", "Network Logs"],
            mitre_claimed=["T1567.004"],
            owners=["admin"],
            reviewers=["reviewer1"],
            tags=["exfiltration", "powershell", "webhook"],
            severity="high",
            false_positives="Legitimate PowerShell scripts using webhooks",
            tuning_guidance="Whitelist known legitimate webhook URLs"
        )
        
        rule1 = RuleRepository.create(
            db,
            use_case_id=uc1.id,
            platform="Windows",
            rule_name="Suspicious PowerShell Webhook",
            rule_text='ProcessName == "powershell.exe" AND CommandLine contains "webhook.site"',
            rule_format="splunk",
            rule_hash=compute_rule_hash(
                'ProcessName == "powershell.exe" AND CommandLine contains "webhook.site"',
                "Windows",
                "splunk"
            ),
            version=1
        )
        
        # Use Case 2: AWS Root Login Without MFA
        uc2 = UseCaseRepository.create(
            db,
            name="AWS Root Login Without MFA",
            description="Detect AWS root account logins without MFA",
            objective="Detect T1078.004 - Cloud Accounts",
            status="review",
            technologies=["AWS"],
            log_sources=["CloudTrail"],
            mitre_claimed=["T1078.004"],
            owners=["contributor1"],
            reviewers=["reviewer1"],
            tags=["aws", "authentication", "mfa"],
            severity="critical",
            false_positives="Initial setup scenarios",
            tuning_guidance="Monitor during initial AWS setup period"
        )
        
        rule2 = RuleRepository.create(
            db,
            use_case_id=uc2.id,
            platform="AWS",
            rule_name="AWS Root Login Without MFA",
            rule_text="eventSource == 'signin.amazonaws.com' AND eventName == 'ConsoleLogin' AND additionalEventData.MFAUsed == 'No'",
            rule_format="splunk",
            rule_hash=compute_rule_hash(
                "eventSource == 'signin.amazonaws.com' AND eventName == 'ConsoleLogin' AND additionalEventData.MFAUsed == 'No'",
                "AWS",
                "splunk"
            ),
            version=1
        )
        
        # Use Case 3: Linux Reverse Shell
        uc3 = UseCaseRepository.create(
            db,
            name="Linux Reverse Shell via Bash",
            description="Detect bash processes creating reverse shell connections",
            objective="Detect T1059.004 - Command and Scripting Interpreter: Unix Shell",
            status="draft",
            technologies=["Linux"],
            log_sources=["Process Logs", "Network Logs"],
            mitre_claimed=["T1059.004"],
            owners=["contributor1"],
            reviewers=[],
            tags=["linux", "execution", "reverse-shell"],
            severity="high",
            false_positives="Legitimate bash scripts using /dev/tcp",
            tuning_guidance="Whitelist known administrative scripts"
        )
        
        rule3 = RuleRepository.create(
            db,
            use_case_id=uc3.id,
            platform="Linux",
            rule_name="Linux Reverse Shell via Bash",
            rule_text='ProcessName == "bash" AND CommandLine matches "/dev/tcp/.*"',
            rule_format="splunk",
            rule_hash=compute_rule_hash(
                'ProcessName == "bash" AND CommandLine matches "/dev/tcp/.*"',
                "Linux",
                "splunk"
            ),
            version=1
        )
        
        db.commit()
        print(f"[OK] Seeded 3 use cases and 3 rules")
        
    except Exception as e:
        db.rollback()
        print(f"[ERROR] Error seeding data: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_demo_data()

