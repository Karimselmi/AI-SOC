"""Optional complementary UI:  streamlit run dashboard.py"""
import json
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI-Powered SOC", layout="wide")
st.title("AI-Powered SOC - incident analysis")
f = Path("reports/incidents.json")
if not f.exists():
    st.info("No incidents yet. Run: python -m soc_agent analyze")
    st.stop()
inc = json.loads(f.read_text())
df = pd.DataFrame(inc)
c1, c2, c3 = st.columns(3)
c1.metric("Incidents", len(df)); c2.metric("Critical/High", int(df["risk_level"].isin(["critical", "high"]).sum()))
c3.metric("Alerts correlated", int(df["n_alerts"].sum()))
st.dataframe(df[["id", "type", "src_ip", "n_alerts", "max_level", "risk_score", "risk_level"]], use_container_width=True)
pick = st.selectbox("Incident", df["id"])
i = next(x for x in inc if x["id"] == pick)
st.subheader(i["type"]); st.write("Evidence", i["evidence"]); st.write("Top rules", i["top_rules"])
st.write("Recommendations (analyst decision)", i["recommendations"])
