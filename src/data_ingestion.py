import pandas as pd
import streamlit as st
from typing import Optional

def load_data(uploaded_file) -> Optional[pd.DataFrame]:
    """
    Loads data from an uploaded CSV or Excel file.
    """
    if uploaded_file is None:
        return None
    
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        elif uploaded_file.name.endswith(('.xlsx', '.xls')):
            df = pd.read_excel(uploaded_file)
        else:
            st.error("Unsupported file format. Please upload .csv or .xlsx.")
            return None
        return df
    except Exception as e:
        st.error(f"Error loading file: {e}")
        return None

def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardizes the input columns to: Rule_Name, Query, Technique_ID, Tactic, Platform.
    Tries to map existing columns if they are close.
    """
    required_columns = {
        'Rule_Name': ['Detection Name', 'Rule Name', 'Name', 'Title', 'Rule_Name'],
        'Query': ['Logic', 'Query', 'Search', 'Rule Logic', 'Logic_Query', 'Logic Query'],
        'Technique_ID': ['MITRE Technique ID', 'Technique ID', 'Technique', 'TID', 'Technique_ID'],
        'Tactic': ['MITRE Tactic', 'Tactic', 'Kill Chain Phase', 'Tactic'],
        'Platform': ['Operational Modes', 'Platform', 'OS', 'Supported Platforms', 'Platforms']
    }
    
    # Create a mapping dictionary
    column_mapping = {}
    for standard_col, variations in required_columns.items():
        found = False
        # Exact/Variation Match
        for col in df.columns:
            # Check if col is exactly in variations or lower-case match
            # Also check if the column name replaces underscore with space or vice versa
            normalized_col = col.lower().replace('_', ' ').strip()
            variation_matches = [v.lower().replace('_', ' ').strip() for v in variations]
            
            if col in variations or col.lower() in [v.lower() for v in variations] or normalized_col in variation_matches:
                column_mapping[col] = standard_col
                found = True
                break
        
        # Fallback: fuzzy search or partial match if needed
        if not found:
             for col in df.columns:
                 if standard_col.lower() in col.lower(): # e.g. "My Rule Name" matches "Rule_Name"
                     column_mapping[col] = standard_col
                     found = True
                     break
            
    if column_mapping:
        df = df.rename(columns=column_mapping)
    
    # Ensure all required columns exist
    for col in required_columns.keys():
        if col not in df.columns:
            df[col] = None # Fill missing with None
            
    return df[list(required_columns.keys())]

