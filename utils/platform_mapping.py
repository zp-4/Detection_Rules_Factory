"""Platform mapping and relationships for MITRE ATT&CK."""

# Standard MITRE platforms
MITRE_PLATFORMS = [
    "Windows",
    "Linux",
    "macOS",
    "AWS",
    "Azure AD",
    "Office 365",
    "SaaS",
    "Google Workspace",
    "IaaS",
    "Network",
    "PRE",
    "Containers"
]

# Platform relationships/mappings
# Maps user-friendly platform names to MITRE platform names
PLATFORM_MAPPING = {
    # Cloud/SaaS platforms
    "Okta": "SaaS",
    "Dropbox": "SaaS",
    "Salesforce": "SaaS",
    "Slack": "SaaS",
    "Microsoft 365": "Office 365",
    "M365": "Office 365",
    "O365": "Office 365",
    "Google Cloud": "Google Workspace",
    "GCP": "Google Workspace",
    "G Suite": "Google Workspace",
    
    # Cloud infrastructure
    "Amazon Web Services": "AWS",
    "Azure": "Azure AD",
    "Microsoft Azure": "Azure AD",
    
    # Operating systems
    "Windows Server": "Windows",
    "Windows 10": "Windows",
    "Windows 11": "Windows",
    "Win": "Windows",
    "Ubuntu": "Linux",
    "CentOS": "Linux",
    "RHEL": "Linux",
    "Red Hat": "Linux",
    "Debian": "Linux",
    "Mac": "macOS",
    "MacOS": "macOS",
    "OSX": "macOS",
    
    # Other
    "Docker": "Containers",
    "Kubernetes": "Containers",
    "K8s": "Containers",
}

# Platform groups (for suggestions)
PLATFORM_GROUPS = {
    "SaaS": ["Okta", "Dropbox", "Salesforce", "Slack", "Google Workspace", "Office 365"],
    "Cloud Infrastructure": ["AWS", "Azure AD", "Google Cloud", "IaaS"],
    "Operating Systems": ["Windows", "Linux", "macOS"],
    "Network": ["Network"],
    "Containers": ["Docker", "Kubernetes", "Containers"]
}

def normalize_platform(platform: str) -> str:
    """Normalize platform name to MITRE standard."""
    if not platform:
        return ""
    
    platform_clean = platform.strip()
    
    # Check direct mapping
    if platform_clean in PLATFORM_MAPPING:
        return PLATFORM_MAPPING[platform_clean]
    
    # Check case-insensitive mapping
    for key, value in PLATFORM_MAPPING.items():
        if platform_clean.lower() == key.lower():
            return value
    
    # Check if already a MITRE platform
    if platform_clean in MITRE_PLATFORMS:
        return platform_clean
    
    # Return original if no mapping found
    return platform_clean

def get_related_platforms(platform: str) -> list:
    """Get related platforms that might be relevant."""
    normalized = normalize_platform(platform)
    
    related = []
    
    # Find group
    for group_name, platforms in PLATFORM_GROUPS.items():
        if normalized in platforms or platform in platforms:
            related.extend([p for p in platforms if p != normalized and p != platform])
            break
    
    return list(set(related))  # Remove duplicates

def suggest_platforms_for_missing(missing_platforms: list, user_platforms: list) -> dict:
    """
    Suggest platform mappings for missing platforms.
    Returns dict mapping missing platform to suggested user platform.
    """
    suggestions = {}
    
    for missing in missing_platforms:
        missing_lower = missing.lower()
        
        # Check if any user platform maps to missing
        for user_plat in user_platforms:
            normalized = normalize_platform(user_plat)
            if normalized.lower() == missing_lower:
                suggestions[missing] = user_plat
                break
        
        # Check platform groups
        if missing not in suggestions:
            for group_name, platforms in PLATFORM_GROUPS.items():
                if missing in platforms:
                    # Find if user has any platform in this group
                    for user_plat in user_platforms:
                        normalized = normalize_platform(user_plat)
                        if normalized in platforms:
                            suggestions[missing] = f"{user_plat} (covers {missing} via {group_name})"
                            break
                    break
    
    return suggestions

