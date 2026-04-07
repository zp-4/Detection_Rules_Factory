"""Session persistence utilities for Streamlit."""
import streamlit as st
import json
import pickle
import hashlib
from typing import Any, Optional
import os
from datetime import datetime

SESSION_FILE = ".streamlit/session_cache.json"
SESSION_TTL = 3600 * 24  # 24 hours

def persist_session_state():
    """Save critical session state to file."""
    try:
        # Only persist important keys
        important_keys = [
            'manual_rules',
            'uploaded_df',
            'analysis_results',
            'analysis_mitre_info',
            'selected_rules',
            'create_rule',
            'edit_rule_id',
            'show_edit_form',
            'last_uploaded_file_name'
        ]
        
        session_data = {}
        for key in important_keys:
            if key in st.session_state:
                # Convert to JSON-serializable format
                value = st.session_state[key]
                if hasattr(value, 'to_dict'):  # pandas DataFrame
                    session_data[key] = {'type': 'dataframe', 'data': value.to_dict()}
                elif isinstance(value, (list, dict, str, int, float, bool, type(None))):
                    session_data[key] = value
                else:
                    # Try to pickle complex objects
                    try:
                        session_data[key] = {'type': 'pickle', 'data': pickle.dumps(value).hex()}
                    except:
                        pass  # Skip if can't serialize
        
        # Add timestamp
        session_data['_timestamp'] = datetime.now().isoformat()
        
        # Save to file
        os.makedirs('.streamlit', exist_ok=True)
        with open(SESSION_FILE, 'w') as f:
            json.dump(session_data, f, default=str)
    except Exception as e:
        # Silently fail - session persistence is optional
        pass

def restore_session_state():
    """Restore session state from file."""
    try:
        if not os.path.exists(SESSION_FILE):
            return
        
        # Check file age
        file_age = datetime.now().timestamp() - os.path.getmtime(SESSION_FILE)
        if file_age > SESSION_TTL:
            # Session expired, clear it
            clear_session_cache()
            return
        
        with open(SESSION_FILE, 'r') as f:
            session_data = json.load(f)
        
        # Remove timestamp if present
        session_data.pop('_timestamp', None)
        
        for key, value in session_data.items():
            if key not in st.session_state:
                if isinstance(value, dict) and 'type' in value:
                    if value['type'] == 'dataframe':
                        import pandas as pd
                        st.session_state[key] = pd.DataFrame(value['data'])
                    elif value['type'] == 'pickle':
                        st.session_state[key] = pickle.loads(bytes.fromhex(value['data']))
                else:
                    st.session_state[key] = value
    except Exception as e:
        # Silently fail - session persistence is optional
        pass

def clear_session_cache():
    """Clear the session cache file."""
    try:
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
    except:
        pass

