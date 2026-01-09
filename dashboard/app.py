import streamlit as st
import json
import glob

st.title("SentinelLine Audit Dashboard")

files = glob.glob("/logs/*.jsonl")

for file in files:
    st.subheader(file)
    with open(file) as f:
        for line in f:
            st.json(json.loads(line))
