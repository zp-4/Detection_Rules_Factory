import openai
import json
from typing import Dict, Any, Optional, List

class AIEngine:
    def __init__(self, api_key: str, provider: str = "openai", base_url: Optional[str] = None, model_name: Optional[str] = None):
        """
        Initialize AI Engine with OpenAI, Gemini, or custom LLM (Llama, etc.).
        
        Args:
            api_key: API key for the selected provider (can be empty for local LLMs)
            provider: "openai", "gemini", or "llama" (for custom OpenAI-compatible LLM)
            base_url: Custom API endpoint URL (required for "llama" provider)
                      Examples: 
                        - Ollama: "http://localhost:11434/v1"
                        - vLLM: "http://localhost:8000/v1"
                        - text-generation-inference: "http://localhost:8080/v1"
                        - LM Studio: "http://localhost:1234/v1"
            model_name: Custom model name (optional, defaults based on provider)
        """
        self.provider = provider.lower()
        self.model_name = model_name
        self.base_url = base_url
        
        if self.provider == "openai":
            self.client = openai.OpenAI(api_key=api_key)
            self.model_name = model_name or "gpt-4o"
            
        elif self.provider == "gemini":
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                self.client = genai.GenerativeModel(model_name or 'gemini-pro')
            except ImportError:
                raise ImportError("google-generativeai package is required for Gemini. Install it with: pip install google-generativeai")
                
        elif self.provider == "llama":
            # Llama/Custom LLM with OpenAI-compatible API
            if not base_url:
                raise ValueError("base_url is required for 'llama' provider. Example: 'http://localhost:11434/v1'")
            
            # Use OpenAI client with custom base URL
            self.client = openai.OpenAI(
                api_key=api_key if api_key else "not-needed",  # Some local LLMs don't need an API key
                base_url=base_url
            )
            # Default model names for common Llama deployments
            self.model_name = model_name or "llama3"  # Can be overridden
            
        else:
            raise ValueError(f"Unsupported provider: {provider}. Use 'openai', 'gemini', or 'llama'")

    def analyze_coverage(self, 
                        technique_id: str, 
                        technique_name: str, 
                        mitre_detection_desc: str,
                        data_components: List[str],
                        mitre_analytics: List[str], 
                        user_query: str, 
                        platform: str,
                        detection_strategies: List[dict],
                        data_sources: List[str],
                        technique_url: str,
                        missing_platforms: Optional[List[str]] = None,
                        mitre_platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyzes if the user query satisfies the MITRE detection description.
        """
        
        analytics_context = ""
        if mitre_analytics:
            analytics_context = "\n        - CRITICAL: The following MITRE Analytics (CAR/Analytic Rules) describe specific behaviors to detect. Does the query cover these?\n" + "\n".join([f"          * {a}" for a in mitre_analytics])

        ds_context = ""
        if detection_strategies:
            ds_lines = []
            for ds in detection_strategies:
                det_id = ds.get("det_id", "DET")
                name = ds.get("name", "")
                url = ds.get("url", "")
                ds_lines.append(f"          * {det_id}: {name} ({url})")
            ds_context = "\n        - Detection Strategies:\n" + "\n".join(ds_lines)

        data_sources_context = ""
        if data_sources:
            data_sources_context = f"\n        - Data Sources: {', '.join(data_sources)}"
        
        missing_platforms_context = ""
        if missing_platforms and len(missing_platforms) > 0:
            missing_platforms_context = f"\n        - MISSING PLATFORMS: The following MITRE platforms are NOT covered by this rule: {', '.join(missing_platforms)}"
            missing_platforms_context += f"\n        - MITRE REQUIRED PLATFORMS: {', '.join(mitre_platforms) if mitre_platforms else 'N/A'}"
            missing_platforms_context += f"\n        - USER SPECIFIED PLATFORMS: {platform}"
        
        mitre_platforms_context = ""
        if mitre_platforms:
            mitre_platforms_context = f"\n        - MITRE Required Platforms: {', '.join(mitre_platforms)}"

        prompt = f"""
        You are a Cybersecurity Specialist and MITRE ATT&CK Expert with deep expertise in SIEM detection rule development.
        
        Task: Analyze if the provided SIEM query effectively covers the MITRE ATT&CK Technique and provide detailed, actionable recommendations.
        
        Context:
        - Technique: {technique_id} - {technique_name}
        - MITRE Page: {technique_url}
        - User Specified Platform: {platform}
        {mitre_platforms_context}
        - MITRE General Detection Guidance: "{mitre_detection_desc}"
        - Relevant Data Components: {", ".join(data_components) if data_components else "General system logs"}
        {analytics_context}
        {ds_context}
        {data_sources_context}
        {missing_platforms_context}

        User SIEM Query:
        "{user_query}"
        
        Analysis Requirements:
        1. Does this query satisfy the requirements of the detection guidance?
        2. CRITICAL: Check if the query logic aligns with the specific Analytics listed above. If an Analytic ID (ANxxxx) is listed but the query misses its specific indicators (e.g. parent process, specific flag), mark it as a GAP.
        3. Identify any logic gaps (e.g., missing command line arguments, parent process checks, or file paths).
        4. PLATFORM ANALYSIS: Analyze the missing platforms and the query context:
           - If the query uses specific service logs (e.g., Okta, Azure AD, AWS CloudTrail), suggest appropriate platform tags:
             * SaaS services (Okta, Office365, Google Workspace) → suggest tags: "saas", "cloud"
             * IaaS services (AWS, Azure, GCP) → suggest tags: "iaas", "cloud"
             * Network-based detections → suggest tags: "network"
             * Endpoint-based detections → suggest tags: "endpoint"
             * Multi-platform detections → suggest all relevant tags
           - Recommend adding missing platform tags based on the detection logic and data sources used
           - If the rule should cover additional platforms, suggest which platforms to add
        5. Provide DETAILED improvement suggestions that include:
           - Specific field names and values to add
           - Example detection queries (in Splunk, Sigma, or KQL format) that demonstrate the improvements
           - Explanation of why each improvement reduces false positives or false negatives
           - Best practices for this specific technique
           - Platform tag recommendations based on the detection context
        6. If the query is completely insufficient, provide a complete example of a well-structured detection rule for this technique.
        
        Output Format (JSON):
        {{
            "satisfies_requirements": boolean,
            "coverage_score": "Low/Medium/High",
            "gap_analysis": "string (detailed explanation of gaps, 2-3 sentences minimum)",
            "improvement_suggestion": "string (comprehensive recommendation, 4-6 sentences minimum, including specific examples and field names)",
            "pseudo_code_recommendation": "string (complete example detection rule in the same format as user query, showing improved version)",
            "recommended_tags": ["tag1", "tag2", ...] (list of recommended tags based on platform analysis, e.g., ["saas", "iaas", "cloud", "network", "endpoint"]),
            "platform_recommendations": "string (explanation of which platforms should be added/removed and why, based on the detection logic)"
        }}
        
        IMPORTANT: 
        - The improvement_suggestion must be detailed and structured. Include:
          * What specific fields/indicators are missing
          * Why they are important for this technique
          * Concrete examples of how to add them
          * Example detection query snippets showing the improvements
        - The recommended_tags should reflect the actual detection context:
          * If query uses Okta logs → include "saas", "cloud"
          * If query uses AWS logs → include "iaas", "cloud", "aws"
          * If query uses network data → include "network"
          * If query uses endpoint logs → include "endpoint"
          * Consider all data sources and detection methods used
        - The platform_recommendations should explain which MITRE platforms are missing and should be added to the rule
        """
        
        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                content = response.choices[0].message.content
                return json.loads(content)
            
            elif self.provider == "gemini":
                full_prompt = f"""You are a helpful cybersecurity assistant.

{prompt}

Please respond with valid JSON only."""
                response = self.client.generate_content(full_prompt)
                content = response.text.strip()
                # Remove markdown code blocks if present
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                return json.loads(content)
            
            elif self.provider == "llama":
                # Llama/Custom LLM using OpenAI-compatible API
                full_prompt = f"""You are a helpful cybersecurity assistant.

{prompt}

IMPORTANT: Respond with valid JSON only. No markdown, no explanations, just the JSON object."""
                try:
                    # Try with response_format if supported
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a helpful cybersecurity assistant. Always respond with valid JSON only."},
                            {"role": "user", "content": full_prompt}
                        ],
                        response_format={"type": "json_object"}
                    )
                except Exception:
                    # Fallback without response_format for older models
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a helpful cybersecurity assistant. Always respond with valid JSON only."},
                            {"role": "user", "content": full_prompt}
                        ]
                    )
                content = response.choices[0].message.content.strip()
                # Remove markdown code blocks if present
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                return json.loads(content)
            
        except json.JSONDecodeError as e:
            return {
                "satisfies_requirements": False,
                "coverage_score": "Error",
                "gap_analysis": f"AI Analysis failed: Invalid JSON response. {str(e)}",
                "improvement_suggestion": "Check API key and connectivity.",
                "pseudo_code_recommendation": None,
                "recommended_tags": [],
                "platform_recommendations": ""
            }
        except Exception as e:
            return {
                "satisfies_requirements": False,
                "coverage_score": "Error",
                "gap_analysis": f"AI Analysis failed: {str(e)}",
                "improvement_suggestion": "Check API key and connectivity.",
                "pseudo_code_recommendation": None,
                "recommended_tags": [],
                "platform_recommendations": ""
            }
    
    def analyze_mitre_mapping(self,
                              rule_name: str,
                              rule_text: str,
                              current_technique_id: Optional[str],
                              current_technique_name: Optional[str],
                              platform: str,
                              rule_format: str) -> Dict[str, Any]:
        """
        Analyzes the MITRE mapping of a detection rule and suggests improvements.
        Can suggest alternative techniques or multi-mapping (2-3 techniques).
        """
        
        current_mapping_context = ""
        if current_technique_id:
            current_mapping_context = f"""
        - Current MITRE Mapping: {current_technique_id} - {current_technique_name}
        - This mapping may be incorrect or incomplete. Analyze if this is the best fit.
        """
        else:
            current_mapping_context = """
        - Current MITRE Mapping: NONE (rule is not mapped to any MITRE technique)
        - This rule needs to be mapped to appropriate MITRE technique(s).
        """
        
        prompt = f"""
        You are a Cybersecurity Specialist and MITRE ATT&CK Expert with deep expertise in threat detection and technique mapping.
        
        Task: Analyze the provided detection rule and determine the most appropriate MITRE ATT&CK technique(s) mapping.
        
        Rule Information:
        - Rule Name: {rule_name}
        - Platform: {platform}
        - Format: {rule_format}
        {current_mapping_context}
        
        Detection Rule Query:
        "{rule_text}"
        
        Analysis Requirements:
        1. Analyze what the rule is actually detecting based on its logic, fields, and patterns.
        2. Identify the PRIMARY MITRE ATT&CK technique that best matches this rule.
        3. Determine if this rule could detect MULTIPLE techniques (2-3 techniques) simultaneously:
           - Some rules detect behaviors that span multiple techniques
           - For example, a rule detecting suspicious PowerShell execution might map to both T1059.001 (PowerShell) and T1566 (Phishing)
           - If the rule logic clearly indicates detection of multiple distinct attack patterns, suggest multi-mapping
        4. If the current mapping exists, evaluate if it's correct:
           - Is the current technique the best match?
           - Should it be changed to a different technique?
           - Should it be expanded to include additional techniques (multi-mapping)?
        5. For each suggested technique, provide:
           - Technique ID (e.g., T1059.001)
           - Technique Name
           - Tactic(s) it belongs to
           - Confidence level (High/Medium/Low)
           - Reasoning why this technique matches the rule
        
        Output Format (JSON):
        {{
            "current_mapping_accuracy": "Correct/Incorrect/Partially Correct/Unknown",
            "primary_technique": {{
                "technique_id": "TXXXX.XXX",
                "technique_name": "Full technique name",
                "tactics": ["tactic1", "tactic2"],
                "confidence": "High/Medium/Low",
                "reasoning": "Why this is the primary technique"
            }},
            "alternative_technique": {{
                "technique_id": "TXXXX.XXX or null",
                "technique_name": "Full technique name or null",
                "tactics": ["tactic1"] or null,
                "confidence": "High/Medium/Low or null",
                "reasoning": "Why this alternative might be better (if current mapping is incorrect)"
            }},
            "multi_mapping": [
                {{
                    "technique_id": "TXXXX.XXX",
                    "technique_name": "Full technique name",
                    "tactics": ["tactic1"],
                    "confidence": "High/Medium/Low",
                    "reasoning": "Why this technique is detected by this rule"
                }}
            ],
            "recommendation": "string (overall recommendation: keep current, change to alternative, or use multi-mapping)",
            "recommendation_reasoning": "string (detailed explanation of the recommendation, 3-5 sentences)"
        }}
        
        IMPORTANT:
        - If the rule clearly detects a single technique, set alternative_technique to null and multi_mapping to empty array
        - If the rule detects multiple distinct attack patterns, populate multi_mapping with 2-3 techniques (max 3)
        - Confidence should be High if the rule logic clearly matches the technique, Medium if partially matches, Low if it's a stretch
        - Be specific in reasoning - reference actual fields, patterns, or behaviors in the rule
        """
        
        try:
            if self.provider == "openai":
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a helpful cybersecurity assistant specializing in MITRE ATT&CK framework."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                content = response.choices[0].message.content
                return json.loads(content)
            
            elif self.provider == "gemini":
                full_prompt = f"""You are a helpful cybersecurity assistant specializing in MITRE ATT&CK framework.

{prompt}

Please respond with valid JSON only."""
                response = self.client.generate_content(full_prompt)
                content = response.text.strip()
                # Remove markdown code blocks if present
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                return json.loads(content)
            
            elif self.provider == "llama":
                # Llama/Custom LLM using OpenAI-compatible API
                full_prompt = f"""You are a helpful cybersecurity assistant specializing in MITRE ATT&CK framework.

{prompt}

IMPORTANT: Respond with valid JSON only. No markdown, no explanations, just the JSON object."""
                try:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a helpful cybersecurity assistant specializing in MITRE ATT&CK framework. Always respond with valid JSON only."},
                            {"role": "user", "content": full_prompt}
                        ],
                        response_format={"type": "json_object"}
                    )
                except Exception:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a helpful cybersecurity assistant specializing in MITRE ATT&CK framework. Always respond with valid JSON only."},
                            {"role": "user", "content": full_prompt}
                        ]
                    )
                content = response.choices[0].message.content.strip()
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                return json.loads(content)
            
        except json.JSONDecodeError as e:
            return {
                "current_mapping_accuracy": "Error",
                "primary_technique": None,
                "alternative_technique": None,
                "multi_mapping": [],
                "recommendation": f"AI Analysis failed: Invalid JSON response. {str(e)}",
                "recommendation_reasoning": "Check API key and connectivity."
            }
        except Exception as e:
            return {
                "current_mapping_accuracy": "Error",
                "primary_technique": None,
                "alternative_technique": None,
                "multi_mapping": [],
                "recommendation": f"AI Analysis failed: {str(e)}",
                "recommendation_reasoning": "Check API key and connectivity."
            }

    @staticmethod
    def _normalize_cti_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure not_applicable responses never include invented rules."""
        if not isinstance(data, dict):
            return {
                "rules": [],
                "summary": "The AI returned an invalid response format. This content cannot be processed as CTI.",
                "not_applicable": True,
            }
        if data.get("not_applicable"):
            data["rules"] = []
        return data

    def analyze_cti_for_detection_rules(self, cti_content: str, source_type: str = "text", source_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyzes CTI content (article, report, etc.) and proposes 1-3 detection rules.
        
        Args:
            cti_content: The CTI content text
            source_type: Type of source (text, pdf, excel, url)
            source_url: Optional URL of the source article (helps provide context)
            
        Returns:
            Dictionary with proposed rules containing all fields needed to create a rule
        """
        url_context = ""
        if source_url:
            url_context = f"\nSource Article URL: {source_url}\n(This URL may provide additional context about the threat intelligence)"
        
        prompt = f"""You are a cybersecurity detection engineer analyzing Cyber Threat Intelligence (CTI) to identify detection opportunities.

CTI Source Type: {source_type}{url_context}
CTI Content:
{cti_content}

STEP 1 — RELEVANCE GATE (MANDATORY, IN ENGLISH):
First decide whether the text is **usable cyber threat intelligence** suitable for deriving detection rules.

The content IS NOT usable if ANY of these apply:
- Casual chat, jokes, personal opinions, poetry, recipes, random unrelated topics, test strings, or nonsense (e.g. "I like chickens", "hello world", single meaningless lines).
- No describable threat actor behavior, intrusion activity, malware families, campaigns, TTPs, attack lifecycle, or security-relevant technical facts.
- Only generic filler with no security substance.

If the content is **NOT** usable CTI, you MUST respond with **ONLY** this JSON shape (no invented rules):
{{
    "rules": [],
    "summary": "A clear English explanation that the provided content is not exploitable as threat intelligence and does not support meaningful behavioral detection rules.",
    "not_applicable": true
}}

If the content **IS** usable CTI (reports, advisories, incident write-ups, malware analysis, campaign details, TTP descriptions with enough substance), set `"not_applicable": false` and continue to STEP 2.

STEP 2 — DETECTION RULES (only when not_applicable is false):
Analyze the CTI and propose 1-3 detection rules that would help detect the threats described.

CRITICAL: Focus on BEHAVIORAL DETECTION RULES WITH CORRELATION, NOT IOC-based rules.

IMPORTANT REQUIREMENTS:
- ❌ DO NOT create rules based solely on static IOCs (IP addresses, file hashes, domain names, filenames alone)
- ✅ CREATE rules that detect BEHAVIORS and ACTIVITY PATTERNS with CORRELATION
- ✅ Rules MUST correlate MULTIPLE events/behaviors together (minimum 2-3 correlated events)
- ✅ Focus on detecting ATTACK BEHAVIORS and TECHNIQUES, not specific artifacts

Examples of EXCELLENT behavioral correlation rules (in Sigma format):
  * PowerShell process making outbound network connections to external IPs within 30 seconds (with Sigma selection/condition)
  * Process execution from temporary directory followed by network connection AND registry modification (correlated in Sigma)
  * Scheduled task creation with encoded command-line arguments AND network connection AND file creation (multi-event correlation)
  * Multiple failed authentication attempts from same source IP followed by successful login from different IP (temporal correlation)
  * Process spawning unusual child processes with network activity to non-standard ports (behavioral pattern)
  * File download from external source followed by execution AND network connection within 60 seconds (correlation)

CRITICAL FORMAT REQUIREMENT - SIGMA FORMAT:
- DEFAULT format is SIGMA (YAML-based detection rule format), NOT Splunk SPL
- Sigma rules MUST use proper YAML structure with these fields:
  * title: Rule name
  * id: Unique identifier
  * description: What the rule detects
  * logsource: Data source (e.g., product: windows, service: security)
  * detection: Contains selection, condition, and optional filters
  * falsepositives: Known false positive scenarios
  * level: Severity (low, medium, high, critical)
  * tags: MITRE ATT&CK tags

Example Sigma YAML format:
---
title: Suspicious PowerShell Network Activity
id: abc123-def456
description: Detects PowerShell process making network connections to external IPs
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        ProcessCommandLine|contains: 'powershell'
        ParentProcessName|endswith: '\\cmd.exe'
    network:
        DestinationIp|re: '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        DestinationPort|re: '^(443|80|8080|4444)$'
    condition: selection and network
    timeframe: 30s
    filter:
        ProcessCommandLine|contains: 'legitimate_script.ps1'
falsepositives:
    - Legitimate PowerShell scripts making network connections
level: medium
tags:
    attack.tactic: execution
    attack.technique: T1059.001

IMPORTANT: Generate rule_text in SIGMA YAML format, NOT Splunk SPL format. Use YAML syntax with proper indentation.

Examples of BAD rules to AVOID:
  * ❌ "Detect IP address 192.168.1.100" (static IOC)
  * ❌ "Detect file hash abc123..." (static IOC)
  * ❌ "Detect domain evil.com" (static IOC)
  * ❌ "Detect PowerShell execution" (no correlation, too broad)
  * ❌ "Network connection to *.com with svchost.exe" (too broad, high false positive - legitimate svchost.exe connects to many .com domains)
  * ❌ "Any process connecting to *.com, *.icu, *.cyou" (too generic, will generate massive false positives)
  * ❌ Rules that match common legitimate behaviors without additional correlation (e.g., just "domain contains .com")

CRITICAL: FALSE POSITIVE CONSIDERATION
- Rules MUST minimize false positives by being SPECIFIC and using CORRELATION
- Avoid overly broad patterns that match legitimate activity (e.g., "any connection to .com", "any PowerShell execution")
- Use EXCLUSIONS for known legitimate behaviors when possible
- Combine MULTIPLE suspicious indicators to reduce false positives
- Prefer detecting UNUSUAL combinations of events rather than common single events
- Example: Instead of "svchost.exe connecting to .com" (high false positive), use "svchost.exe connecting to suspicious TLDs (.icu, .cyou) AND process spawned from unusual parent AND no recent legitimate activity pattern"

Rules should:
- Correlate process execution + network activity + file/registry activity
- Detect attack TECHNIQUES and BEHAVIORS that persist even if IOCs change
- Use temporal correlation (events happening within time windows)
- Combine multiple data sources (process + network + file + registry + authentication)
- Focus on MITRE ATT&CK techniques and TTPs, not specific artifacts
- MINIMIZE FALSE POSITIVES through specificity and correlation
- Exclude or whitelist known legitimate patterns when appropriate

For each proposed rule, provide:
1. rule_name: A clear, descriptive name for the detection rule
2. rule_text: The actual detection query/logic with CORRELATION of multiple events/behaviors. MUST include at least 2-3 correlated events (e.g., process execution AND network connection AND file activity). Use temporal correlation (events within time windows). IMPORTANT: Format should be SIGMA format by default (YAML-based detection rule format). If Sigma format is not appropriate, use a generic format that can be adapted. For Sigma format, use proper YAML structure with fields like: selection (with field mappings), condition, and filters.
3. platform: The target platform(s) (Windows, Linux, macOS, Cloud, Network, etc.)
4. rule_format: Suggested format (default: sigma, or splunk, kql, yara, snort, other)
5. mitre_technique_id: The most relevant MITRE ATT&CK technique ID (e.g., T1059.001) or null if unclear
6. tags: List of relevant tags (e.g., ["endpoint", "execution", "powershell", "network", "correlation"])
7. reasoning: Brief explanation of why this rule is relevant based on the CTI and what behaviors it detects
8. confidence: Confidence level (high, medium, low) for this rule proposal

Focus on:
- BEHAVIORAL patterns and attack techniques, not static IOCs
- CORRELATION of multiple events (process + network + file + registry, etc.)
- Rules that would catch the threat early in the attack chain through behavior
- Rules that are practical and have low false positive potential through correlation
- Clear mapping to MITRE ATT&CK techniques when possible
- Detection of TTPs (Tactics, Techniques, and Procedures) rather than specific artifacts

When not_applicable is false, respond with a JSON object in this exact format:
{{
    "not_applicable": false,
    "rules": [
        {{
            "rule_name": "Detection Rule Name",
            "rule_text": "Sigma YAML format detection rule here (with selection, condition, filters, etc.)",
            "platform": "Windows",
            "rule_format": "sigma",
            "mitre_technique_id": "T1059.001",
            "tags": ["endpoint", "execution"],
            "reasoning": "Why this rule is relevant",
            "confidence": "high"
        }}
    ],
    "summary": "Brief summary of the CTI and detection opportunities identified"
}}

Remember: never fabricate rules to satisfy the user when the input is not real CTI. An empty rules array with not_applicable true is the correct response for non-exploitable content."""

        try:
            if self.provider == "openai":
                # Try with response_format first (for GPT-4 and compatible models)
                try:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity detection engineer. If the input is not real threat intelligence, respond with JSON: rules=[], not_applicable=true, and an English summary explaining the content is not exploitable. Never invent detection rules for jokes or unrelated text."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.2,
                        response_format={"type": "json_object"}
                    )
                    content = response.choices[0].message.content.strip()
                    return self._normalize_cti_response(json.loads(content))
                except Exception as format_error:
                    # If response_format is not supported, try without it
                    if "response_format" in str(format_error) or "json_object" in str(format_error):
                        response = self.client.chat.completions.create(
                            model=self.model_name,
                            messages=[
                                {"role": "system", "content": "You are a cybersecurity detection engineer. If the input is not real threat intelligence, respond with JSON: rules=[], not_applicable=true. Never invent rules for unrelated text. Respond ONLY with valid JSON."},
                                {"role": "user", "content": prompt}
                            ],
                            temperature=0.2
                        )
                        content = response.choices[0].message.content.strip()
                        # Remove markdown code blocks if present
                        if content.startswith("```json"):
                            content = content[7:]
                        if content.startswith("```"):
                            content = content[3:]
                        if content.endswith("```"):
                            content = content[:-3]
                        content = content.strip()
                        return self._normalize_cti_response(json.loads(content))
                    else:
                        raise format_error
                        
            elif self.provider == "gemini":
                full_prompt = f"""You are a cybersecurity detection engineer analyzing Cyber Threat Intelligence (CTI) to identify detection opportunities.

{prompt}

Please respond with valid JSON only."""
                response = self.client.generate_content(full_prompt)
                content = response.text.strip()
                # Remove markdown code blocks if present
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                return self._normalize_cti_response(json.loads(content))
                
            elif self.provider == "llama":
                # Llama/Custom LLM using OpenAI-compatible API
                full_prompt = f"""You are a cybersecurity detection engineer analyzing Cyber Threat Intelligence (CTI) to identify detection opportunities.

{prompt}

IMPORTANT: Respond with valid JSON only. No markdown, no explanations, just the JSON object."""
                try:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity detection engineer. If the input is not real threat intelligence, respond with JSON: rules=[], not_applicable=true. Never invent rules for unrelated text. Always respond with valid JSON only."},
                            {"role": "user", "content": full_prompt}
                        ],
                        temperature=0.2,
                        response_format={"type": "json_object"}
                    )
                except Exception:
                    response = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity detection engineer. If the input is not real threat intelligence, respond with JSON: rules=[], not_applicable=true. Never invent rules for unrelated text. Always respond with valid JSON only."},
                            {"role": "user", "content": full_prompt}
                        ],
                        temperature=0.2
                    )
                content = response.choices[0].message.content.strip()
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                return self._normalize_cti_response(json.loads(content))
                
        except json.JSONDecodeError as e:
            return {
                "rules": [],
                "summary": f"Error parsing AI response: {str(e)}",
                "error": "Invalid JSON response from AI",
                "not_applicable": True,
            }
        except Exception as e:
            return {
                "rules": [],
                "summary": f"Error analyzing CTI: {str(e)}",
                "error": str(e),
                "not_applicable": True,
            }