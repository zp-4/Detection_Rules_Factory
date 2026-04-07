import requests
import json
import os
import pandas as pd
from typing import Dict, List, Any, Optional
from mitreattack.stix20 import MitreAttackData

MITRE_ENTERPRISE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = "enterprise-attack.json"


def _stix_obj_attr(obj: Any, attr: str, default: Any = None) -> Any:
    """Read attribute from STIX object (class or dict)."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def list_software_for_group(mitre_attack_data: MitreAttackData, group_stix_id: str) -> List[Dict[str, Any]]:
    """
    Software (malware + tools) linked to a threat actor group in MITRE ATT&CK.
    Uses mitreattack (including software from campaigns attributed to the group).

    Exposed at module level so callers can use ``mitre_engine.mitre_attack_data`` when the
    ``MitreEngine`` instance may be a stale cached reference without newer methods.
    """
    try:
        entries = mitre_attack_data.get_software_used_by_group(group_stix_id)
        seen: Dict[str, Dict[str, Any]] = {}

        for entry in entries:
            sw = None
            if isinstance(entry, dict):
                sw = entry.get("object")
            else:
                sw = getattr(entry, "object", None)
            if sw is None:
                continue

            stix_id = _stix_obj_attr(sw, "id")
            if not stix_id or stix_id in seen:
                continue

            name = _stix_obj_attr(sw, "name") or "Unknown"
            ext_refs = _stix_obj_attr(sw, "external_references") or []
            attack_id: Optional[str] = None
            url: Optional[str] = None
            for ref in ext_refs:
                if isinstance(ref, dict):
                    rs = ref.get("source_name", "")
                    rid = ref.get("external_id", "")
                    rurl = ref.get("url", "")
                else:
                    rs = getattr(ref, "source_name", "")
                    rid = getattr(ref, "external_id", "")
                    rurl = getattr(ref, "url", "")
                if rs == "mitre-attack" and rid:
                    attack_id = rid
                    url = rurl or url
                    break

            sw_type = _stix_obj_attr(sw, "type") or ""
            platforms = _stix_obj_attr(sw, "x_mitre_platforms") or []

            if not url and attack_id:
                url = f"https://attack.mitre.org/software/{attack_id}/"

            seen[stix_id] = {
                "attack_id": attack_id or "",
                "name": name,
                "type": sw_type,
                "platforms": platforms if isinstance(platforms, list) else [],
                "url": url or "",
                "stix_id": stix_id,
            }

        return sorted(
            seen.values(),
            key=lambda x: (x.get("attack_id") or "ZZZ", x.get("name") or ""),
        )
    except Exception as e:
        print(f"Error fetching software for group {group_stix_id}: {e}")
        return []


class MitreEngine:
    def __init__(self, force_refresh=False):
        # Only download if file doesn't exist or force_refresh is True
        self._ensure_data_exists(force_refresh=force_refresh)
        self.mitre_attack_data = MitreAttackData(CACHE_FILE)

    def _ensure_data_exists(self, force_refresh=False):
        """Ensures the enterprise-attack.json file exists locally."""
        if os.path.exists(CACHE_FILE) and not force_refresh:
            # File exists, just verify it's valid JSON
            try:
                with open(CACHE_FILE, 'r') as f:
                    json.load(f)
                # File is valid, no need to download
                return
            except (json.JSONDecodeError, IOError):
                # File is corrupted or unreadable, will download below
                pass
        
        # Download only if file doesn't exist, is invalid, or force refresh requested
        if force_refresh:
            print(f"Refreshing MITRE ATT&CK data from {MITRE_ENTERPRISE_JSON_URL}...")
        else:
            print(f"Downloading MITRE ATT&CK data from {MITRE_ENTERPRISE_JSON_URL}...")
        
        response = requests.get(MITRE_ENTERPRISE_JSON_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        with open(CACHE_FILE, 'w') as f:
            json.dump(data, f)
        
        if force_refresh:
            print(f"MITRE ATT&CK data refreshed and cached successfully.")
        else:
            print(f"MITRE ATT&CK data downloaded and cached successfully.")
    
    def refresh_data(self):
        """Force refresh of MITRE ATT&CK data."""
        self._ensure_data_exists(force_refresh=True)
        # Reinitialize the MitreAttackData object with fresh data
        self.mitre_attack_data = MitreAttackData(CACHE_FILE)

    def get_technique_details(self, technique_id: str) -> Dict[str, Any]:
        """
        Fetches detailed information about a technique using the MITRE SDK.
        Includes Data Sources, Data Components, and Detection Strategies (Analytics).
        """
        try:
            # Clean technique ID (remove any whitespace)
            technique_id = technique_id.strip() if technique_id else ""
            if not technique_id:
                return {}
            
            # Get the technique object (attack-pattern)
            technique = self.mitre_attack_data.get_object_by_attack_id(technique_id, 'attack-pattern')
            
            if not technique:
                # Try alternative lookup methods
                # Sometimes techniques might be stored differently
                all_techniques = self.mitre_attack_data.get_techniques()
                for tech in all_techniques:
                    tech_obj = tech.object if hasattr(tech, 'object') else tech
                    # Check external references for the technique ID
                    ext_refs = tech_obj.get('external_references', []) if isinstance(tech_obj, dict) else getattr(tech_obj, 'external_references', [])
                    for ref in ext_refs:
                        ref_source = ref.get('source_name') if isinstance(ref, dict) else getattr(ref, 'source_name', '')
                        ref_id = ref.get('external_id') if isinstance(ref, dict) else getattr(ref, 'external_id', '')
                        if ref_source == 'mitre-attack' and ref_id == technique_id:
                            technique = tech_obj if isinstance(tech_obj, dict) else tech
                            break
                    if technique:
                        break
                
                if not technique:
                    return {}

            # Serialize STIX object to dict
            tech_dict = json.loads(technique.serialize())

            # 1. Get Data Components
            data_components_related = self.mitre_attack_data.get_datacomponents_detecting_technique(technique.id)
            data_components_list = []
            for item in data_components_related:
                dc = item.object
                data_components_list.append(dc.name)

            # 2. Get Detection Strategies & Analytics
            # Note: This relies on the dataset containing x-mitre-data-component or similar extended objects.
            # If standard enterprise-attack.json doesn't have them, this might return empty, but the code handles it.
            # The user's screenshot implies these exist in their context or they want us to try fetching them.
            analytics_list = []
            detection_strategies_list = []
            try:
                # Attempt to get detection strategies
                det_strategies = self.mitre_attack_data.get_detection_strategies_detecting_technique(technique.id)
                
                for ds_entry in det_strategies:
                    # ds_entry might be a dict or object depending on library version/context
                    # If it's a dict, access fields with .get() or []
                    # Based on logs: "dict object has no attribute object" -> so it is a dict?
                    
                    ds_obj = None
                    if hasattr(ds_entry, 'object'):
                        ds_obj = ds_entry.object
                    elif isinstance(ds_entry, dict) and 'object' in ds_entry:
                        ds_obj = ds_entry['object']
                    else:
                        # Sometimes the entry itself is the relationship or object if parsed differently
                        # But typically it's RelationshipEntry. 
                        # Let's inspect what ds_entry is if we could.
                        # Assuming it mimics the stix2 object structure.
                        pass

                    if not ds_obj:
                        continue

                    ds_id = ds_obj.get('id') if isinstance(ds_obj, dict) else ds_obj.id

                    # Capture Detection Strategy metadata
                    ds_name = ds_obj.get('name') if isinstance(ds_obj, dict) else getattr(ds_obj, 'name', '')
                    det_id = "Unknown DET"
                    ds_url = ""
                    ext_refs_ds = ds_obj.get('external_references', []) if isinstance(ds_obj, dict) else getattr(ds_obj, 'external_references', [])
                    for ref in ext_refs_ds:
                        ref_source = ref.get('source_name') if isinstance(ref, dict) else getattr(ref, 'source_name', '')
                        ref_id_val = ref.get('external_id') if isinstance(ref, dict) else getattr(ref, 'external_id', '')
                        ref_url = ref.get('url') if isinstance(ref, dict) else getattr(ref, 'url', '')
                        if ref_source and ref_source.lower() == 'mitre-attack':
                            det_id = ref_id_val or det_id
                            ds_url = ref_url or ds_url
                            break
                    detection_strategies_list.append({
                        "det_id": det_id,
                        "name": ds_name,
                        "url": ds_url
                    })

                    # Now get analytics for this strategy
                    analytics = []
                    
                    # Try getting analytics via x_mitre_analytic_refs (Direct link in JSON)
                    # This is the most reliable method based on the debug output showing 'x_mitre_analytic_refs'
                    
                    # Helper to safely get attribute
                    def get_attr_safe(obj, attr, default=None):
                         if isinstance(obj, dict):
                             return obj.get(attr, default)
                         return getattr(obj, attr, default)

                    refs = get_attr_safe(ds_obj, 'x_mitre_analytic_refs', [])
                    for ref_id in refs:
                        try:
                            # Fetch the analytic object directly by STIX ID
                            analytic_obj = self.mitre_attack_data.get_object_by_stix_id(ref_id)
                            if analytic_obj:
                                analytics.append(analytic_obj)
                        except Exception as e:
                            # print(f"Error fetching analytic {ref_id}: {e}")
                            pass

                    # If that failed or was empty, try the SDK relationship methods as fallback
                    if not analytics:
                        if hasattr(self.mitre_attack_data, 'get_analytics_by_detection_strategy'):
                            entries = self.mitre_attack_data.get_analytics_by_detection_strategy(ds_id)
                            analytics = [e.object for e in entries]
                        elif hasattr(self.mitre_attack_data, 'get_analytics_for_detection_strategy'):
                            entries = self.mitre_attack_data.get_analytics_for_detection_strategy(ds_id)
                            analytics = [e.object for e in entries]

                    for analytic in analytics:
                        if not analytic:
                            continue

                        # Helper to safely get attribute
                        def get_attr_safe(obj, attr, default=None):
                             if isinstance(obj, dict):
                                 return obj.get(attr, default)
                             return getattr(obj, attr, default)

                        # Extract Analytic ID
                        an_id = "Unknown ID"
                        ext_refs = get_attr_safe(analytic, 'external_references', [])
                        
                        for ref in ext_refs:
                             # accessing properties of external reference object/dict
                             source_name = get_attr_safe(ref, 'source_name', '')
                             ext_id_val = get_attr_safe(ref, 'external_id', '')
                             
                             if source_name and 'analytic' in source_name.lower():
                                 an_id = ext_id_val
                                 break
                             if ext_id_val and ext_id_val.startswith('AN'):
                                 an_id = ext_id_val
                                 break
                        
                        name = get_attr_safe(analytic, 'name', "Unknown Analytic")
                        desc = get_attr_safe(analytic, 'description', "")
                        
                        # Avoid duplicates
                        entry_str = f"[{an_id}] {name}: {desc}"
                        if entry_str not in analytics_list:
                            analytics_list.append(entry_str)

            except Exception as e:
                print(f"Warning: Could not fetch analytics for {technique_id}: {e}")
                # import traceback
                # traceback.print_exc()
                pass

            return {
                'name': tech_dict.get('name'),
                'description': tech_dict.get('description'),
                'platforms': tech_dict.get('x_mitre_platforms', []),
                'detection': tech_dict.get('x_mitre_detection', ''),
                'data_sources': tech_dict.get('x_mitre_data_sources', []),
                'data_components': data_components_list,
                'analytics': analytics_list, # New field
                'detection_strategies': detection_strategies_list,
                'id': tech_dict.get('id'),
                'technique_url': next(
                    (ref.get('url') for ref in tech_dict.get('external_references', [])
                     if ref.get('source_name') == 'mitre-attack'), '')
            }
        except Exception as e:
            print(f"Error fetching details for {technique_id}: {e}")
            return {}

    def compare_platforms(self, technique_id: str, user_platforms: List[str]) -> List[str]:
        """
        Returns a list of platforms supported by MITRE but missing in user_platforms.
        Uses platform mapping to check relationships (e.g., Okta → SaaS).
        """
        from utils.platform_mapping import normalize_platform, suggest_platforms_for_missing
        
        details = self.get_technique_details(technique_id)
        if not details:
            return []
        
        mitre_platforms = details.get('platforms', [])
        
        # Normalize user platforms
        normalized_user_platforms = [normalize_platform(p) for p in user_platforms if p]
        normalized_user_platforms_set = set(p.lower() for p in normalized_user_platforms)
        
        # Check which MITRE platforms are missing
        missing = []
        for mitre_plat in mitre_platforms:
            mitre_plat_lower = mitre_plat.lower()
            # Check direct match
            if mitre_plat_lower not in normalized_user_platforms_set:
                # Check if any normalized user platform matches
                found = False
                for norm_user_plat in normalized_user_platforms:
                    if norm_user_plat.lower() == mitre_plat_lower:
                        found = True
                        break
                if not found:
                    missing.append(mitre_plat)
        
        return missing

    def get_all_groups(self, remove_revoked_deprecated: bool = True) -> List[Dict[str, Any]]:
        """
        Retrieves all MITRE groups (APT groups) with their details.
        
        Returns:
            List of dictionaries containing group information (id, name, attack_id, description, etc.)
        """
        try:
            groups = self.mitre_attack_data.get_groups(remove_revoked_deprecated=remove_revoked_deprecated)
            result = []
            
            for group in groups:
                # Get group ID (G0016, etc.)
                attack_id = None
                group_url = None
                for ref in group.external_references:
                    if ref.source_name == "mitre-attack":
                        attack_id = ref.external_id
                        group_url = ref.url
                        break
                
                if not attack_id:
                    continue  # Skip groups without MITRE ID
                
                result.append({
                    'id': group.id,
                    'attack_id': attack_id,
                    'name': group.name,
                    'description': group.description if hasattr(group, 'description') else '',
                    'url': group_url,
                    'aliases': group.aliases if hasattr(group, 'aliases') else []
                })
            
            return result
        except Exception as e:
            print(f"Error fetching groups: {e}")
            return []

    def get_techniques_used_by_group(self, group_id: str) -> List[str]:
        """
        Gets all technique IDs used by a specific group.
        
        Args:
            group_id: The STIX ID of the group (not the ATT&CK ID)
            
        Returns:
            List of technique IDs (e.g., ['T1566', 'T1003.002', ...])
        """
        try:
            techs = self.mitre_attack_data.get_techniques_used_by_group(group_id)
            technique_ids = []
            
            for t in techs:
                tech_obj = t['object'] if isinstance(t, dict) and 'object' in t else (t.object if hasattr(t, 'object') else t)
                
                # Get external references
                ext_refs = []
                if hasattr(tech_obj, 'external_references'):
                    ext_refs = tech_obj.external_references
                elif isinstance(tech_obj, dict) and 'external_references' in tech_obj:
                    ext_refs = tech_obj['external_references']
                
                # Find MITRE ATT&CK ID
                for ref in ext_refs:
                    ref_source = ref.source_name if hasattr(ref, 'source_name') else (ref.get('source_name', '') if isinstance(ref, dict) else '')
                    ref_id = ref.external_id if hasattr(ref, 'external_id') else (ref.get('external_id', '') if isinstance(ref, dict) else '')
                    if ref_source == "mitre-attack" and ref_id:
                        technique_ids.append(ref_id)
                        break
            
            return technique_ids
        except Exception as e:
            print(f"Error fetching techniques for group {group_id}: {e}")
            return []

    def get_software_used_by_group(self, group_stix_id: str) -> List[Dict[str, Any]]:
        """
        Software (malware + tools) linked to a threat actor group in MITRE ATT&CK.
        Includes software used via campaigns attributed to the group (per mitreattack).

        Returns:
            List of dicts with: attack_id (Sxxxx), name, type (malware/tool), platforms, url, stix_id
        """
        return list_software_for_group(self.mitre_attack_data, group_stix_id)
