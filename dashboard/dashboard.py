import streamlit as st
import pandas as pd

st.set_page_config(page_title="Security Dashboard", layout="wide")
st.title("🔐 Integrated Security Dashboard (L2 View)")

# Load data
df = pd.read_csv("unified.csv")

# ---------- DERIVED METRICS ----------
df["total_critical"] = df["code_critical"] + df["dependency_critical"]
df["total_high"] = df["code_high"] + df["dependency_high"]

def risk_level(row):
    if row["total_critical"] >= 3:
        return "HIGH"
    elif row["total_high"] >= 5:
        return "MEDIUM"
    else:
        return "LOW"

df["risk_level"] = df.apply(risk_level, axis=1)

# ---------- KPI CARDS ----------
st.subheader("📊 Overall Risk Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Products", len(df))
col2.metric("Total Critical", df["total_critical"].sum())
col3.metric("High Risk Products", len(df[df["risk_level"] == "HIGH"]))
col4.metric("Medium Risk Products", len(df[df["risk_level"] == "MEDIUM"]))

# ---------- PRODUCT TABLE ----------
st.subheader("🧩 Product-Level View")

display_df = df[[
    "product",
    "risk_level",
    "total_critical",
    "total_high",
    "license_risk",
    "last_scan"
]]

st.dataframe(display_df, use_container_width=True)

# ---------- PRODUCT DETAILS ----------
st.subheader("🔍 Product Details")

for _, row in df.iterrows():
    with st.expander(f"Product {row['product']} — Risk: {row['risk_level']}"):
        c1, c2, c3 = st.columns(3)
        c1.metric("Code Critical", row["code_critical"])
        c2.metric("Dependency Critical", row["dependency_critical"])
        c3.metric("License Risk", row["license_risk"])
        st.caption(f"Last Scan: {row['last_scan']}")
