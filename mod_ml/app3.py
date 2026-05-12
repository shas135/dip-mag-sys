import streamlit as st
import torch
import joblib
import pandas as pd
import numpy as np
import plotly.express as px
import os
import traceback
from scapy.all import sniff, IP, TCP, ARP, get_if_list, UDP, ICMP, Ether
from model import load_ids_model
from feature_extractor import pcap_to_dataframe, realtime_work
import json
import requests

# Настройки страницы
st.set_page_config(
    page_title=" Модуль анализа сетевого трафика с использованием обученной модели машинного обучения ",
    layout="wide",
    initial_sidebar_state="expanded" )

# Классы и остальное
classes = ['Benign', 'DDoS', 'DoS', 'Mirai','Recon', 'Spoofing', 'Web', 'BruteForce']
crit = ["DDoS", "Mirai", "ANOMALY"]

protocols = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    58: "ICMPv6"}

# Интерфейс
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root{
    --bg: #f3f4f6;
    --panel: #ffffff;
    --panel-alt: #f8fafc;
    --text: #111827;
    --muted: #6b7280;
    --border: #e5e7eb;
    --accent: #2563eb;
    --danger: #dc2626;
    --success: #16a34a;
    --shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
    --radius: 18px;
}

html, body, .stApp {
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
}

.stApp {
    padding-top: 0.5rem;
}

[data-testid="stSidebar"] {
    background: #ffffff;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] * {
    color: var(--text);
}

.header {
    text-align: center;
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.25;
    color: var(--text);
    letter-spacing: -0.02em;
    margin: 0.5rem 0 1.25rem 0;
}
            
.sub {
    text-align: center;
    color: var(--muted);
    font-size: 0.95rem;
    margin-bottom: 1.25rem;
}

.card {
    position: relative;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.25rem 1.4rem;
    text-align: center;
    box-shadow: var(--shadow);
    transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
}

.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 14px 36px rgba(15, 23, 42, 0.12);
    border-color: #cbd5e1;
}

.danger {
    border-left: 5px solid var(--danger);
}

.title {
    font-size: 0.78rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.5rem;
}

.value {
    font-size: 2.2rem;
    font-weight: 700;
    color: var(--text);
    line-height: 1.1;
}

.footer {
    text-align: center;
    color: var(--muted);
    margin-top: 2.5rem;
    font-size: 0.8rem;
    letter-spacing: 0.04em;
    padding-bottom: 0.5rem;
}

.stButton > button {
    border-radius: 12px;
    border: 1px solid var(--border);
    background: #ffffff;
    color: var(--text);
    font-weight: 600;
    padding: 0.55rem 1rem;
    transition: background 0.15s ease, border-color 0.15s ease, transform 0.15s ease;
}

.stButton > button:hover {
    background: #f3f4f6;
    border-color: #cbd5e1;
    transform: translateY(-1px);
}

.stSelectbox div[data-baseweb="select"] > div,
.stTextInput input,
.stSlider [data-baseweb="slider"] {
    border-radius: 12px;
}

div[data-testid="stDataFrame"] {
    background: var(--panel);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    overflow: hidden;
}

div[data-testid="stPlotlyChart"] {
    background: var(--panel);
    border-radius: var(--radius);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    padding: 0.5rem;
}

hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1rem 0;
}

body, .stApp, p, span, label, div {
    color: #111827 !important;
}

h1, h2, h3, h4, h5, h6 {
    color: #111827 !important;
}

section[data-testid="stSidebar"] * {
    color: #111827 !important;
}

[data-testid="stFileUploader"] {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 10px;
}

[data-testid="stFileUploader"] * {
    color: #111827 !important;
}

[data-testid="stFileUploader"] button {
    background: #f3f4f6 !important;
    color: #111827 !important;
    border: 1px solid #d1d5db !important;
    border-radius: 10px;
}

[data-testid="stFileUploaderDropzone"] {
    background: #f9fafb !important;
    border: 2px dashed #d1d5db !important;
}

[data-testid="stRadio"] label,
[data-testid="stSlider"] label {
    color: #111827 !important;
}

.js-plotly-plot .plotly .main-svg {
    font-family: 'Inter', sans-serif;
}
</style>
""", unsafe_allow_html=True)

# Загрузка модели
@st.cache_resource
def loads():
    model = joblib.load("random_forest_ciciot2023.pkl")
    return model
model = loads()

def pcap_work(pcap):
    try:
        df = pcap_to_dataframe(pcap)
        inform_cols = ["ts", "SourceIP", "DestIP", "SourcePort", "DestPort"]
        df = df.drop(columns = 'DHCP')
        df = df.drop(columns = 'IRC')
        df = df.drop(columns = 'SMTP')
        df = df.drop(columns = 'Telnet')
        feature_cols = [c for c in df.columns if c not in inform_cols]
        X = df[feature_cols].copy()
        preds = model.predict(X)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)
            conf = probs.max(axis=1) * 100
        else:
            conf = np.full(len(df), 101.0)
        df_res = df[inform_cols].copy()
        df_res["Label"] = np.array(classes)[preds]
        #df_res["Confidence %"] = conf
        df_res["Anomaly"] = (df_res["Label"] != "Benign") & (conf > 55)
        df_res = df_res.drop(columns = 'Label')
        return df_res
    except Exception as e: 
        print("pcap_work error:", e)
        print(traceback.format_exc())

def rt_work(df):
    try:
        inform_cols = ["ts", "SourceIP", "DestIP", "SourcePort", "DestPort"]
        df = df.drop(columns = 'DHCP')
        df = df.drop(columns = 'IRC')
        df = df.drop(columns = 'SMTP')
        df = df.drop(columns = 'Telnet')
        feature_cols = [c for c in df.columns if c not in inform_cols]
        X = df[feature_cols].copy()
        preds = model.predict(X)
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)
            conf = probs.max(axis=1) * 100
        else:
            conf = np.full(len(df), 101.0)
        df_res = df[inform_cols].copy()
        df_res["Label"] = np.array(classes)[preds]
        #df_res["Confidence %"] = conf
        df_res["Anomaly"] = (df_res["Label"] != "Benign") & (conf > 55)
        df_res = df_res.drop(columns = 'Label')
        return df_res
    except Exception as e: 
        print("rt_work error:", e)
        print(traceback.format_exc())

def logstash_integr(df, url = "http://localhost:8080"):
    if df is None or df.empty: return
    records = df.to_dict(orient="records")
    for row in records:
        try:
            r = requests.post(
                url,
                data=json.dumps(row),
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"Logstash send error: {e}")

# Заголовок
st.markdown("<div class='header'>Модуль анализа сетевого трафика с использованием обученной модели машинного обучения</div>", unsafe_allow_html=True)

# Боковая панель
with st.sidebar:
    st.markdown("Режимы работы")
    mode = st.radio("Режимы", ["Загрузка pcap на анализ", "Обнаружение в реальном времени с сетевого интерфейса"])
    stop_btn = st.button("Стоп")

if mode == "Загрузка pcap на анализ":
    up = st.file_uploader("Загрузите файл", type=["pcap"])
    if up:
        temp = f"temp_{up.name}"
        with open(temp, "wb") as f:
            f.write(up.getbuffer())
        df_res = pcap_work(temp)
        os.remove(temp)
        if df_res is None or df_res.empty:
            st.error("Не удалось обработать pcap-файл")
            st.stop()
        df = df_res
        stats = { # Статистика
            "t": len(df),
            "a": int(df["Anomaly"].eq(True).sum()),
            "b": int(df["Anomaly"].ne(True).sum())
        }
        anomaly_df = df[df["Anomaly"] == True]
        c1, c2, c3 = st.columns(3)
        c1.markdown(
            f"<div class='card'><div class='title'>Общее количество потоков</div><div class='value'>{stats['t']}</div></div>",
            unsafe_allow_html=True
        )
        c2.markdown(
            f"<div class='card danger'><div class='title'>Количество обнаруженных угроз в потоках</div><div class='value'>{stats['a']}</div></div>",
            unsafe_allow_html=True
        )
        c3.markdown(
            f"<div class='card'><div class='title'>Количество нормальных потоков</div><div class='value'>{stats['b']}</div></div>",
            unsafe_allow_html=True
        )
        # Таблицы
        st.markdown("### Информация о нормальном трафике")
        st.dataframe(df[df["Anomaly"] != True], use_container_width=True, height=380)

        st.markdown("### Информация о трафике с аномалиями")
        st.dataframe(anomaly_df, use_container_width=True, height=380)
        
# Модуль данных с интерфейса
if mode == "Обнаружение в реальном времени с сетевого интерфейса":
    available_ifaces = get_if_list()

    iface = st.selectbox(
        "Выберите сетевой интерфейс",
        available_ifaces if available_ifaces else [""],
        index=0
    )

    if not iface:
        st.warning("Сетевой интерфейс не выбран")
        st.stop()

    capture_seconds = st.slider("Размер блока захвата, сек", 5, 60, 10)
    pkt_limit = st.slider("Лимит строк для отображения", 50, 5000, 500)

    if "running" not in st.session_state:
        st.session_state.running = False

    if "live_df" not in st.session_state:
        st.session_state.live_df = pd.DataFrame()

    col1, col2 = st.columns(2)
    with col1:
        start = st.button("Запуск анализа")
    with col2:
        stop = st.button("Стоп")

    if start:
        st.session_state.running = True

    if stop:
        st.session_state.running = False

    dash = st.empty()
    table = st.empty()
    anomaly_table = st.empty()
    status_box = st.empty()

    if st.session_state.running:
        status_box.info("Идет непрерывный анализ. Каждый цикл обрабатывает новый блок трафика.")

        with st.spinner("Захват и анализ очередного блока..."):
            df_res = realtime_work(
                iface=iface,
                capture_seconds=capture_seconds,
                subfiles_size=10,
                n_threads=4
            )

        if df_res is not None and not df_res.empty:
            df_chunk = rt_work(df_res)

            if df_chunk is not None and not df_chunk.empty:
                # накопление результатов
                st.session_state.live_df = pd.concat(
                    [st.session_state.live_df, df_chunk],
                    ignore_index=True
                )

                # ограничение памяти / размера таблицы
                if len(st.session_state.live_df) > pkt_limit:
                    st.session_state.live_df = st.session_state.live_df.tail(pkt_limit).reset_index(drop=True)

        # перезапуск следующего цикла
        if st.session_state.running:
            st.rerun()

    # отображение текущего состояния
    if not st.session_state.live_df.empty:
        df = st.session_state.live_df.copy()
        anomaly_df = df[df["Anomaly"] == True]
        logstash_integr(df)
        
        stats = {
            "t": len(df),
            "a": int(df["Anomaly"].eq(True).sum()),
            "b": int(df["Anomaly"].ne(True).sum())
        }

        c1, c2, c3 = st.columns(3)
        c1.markdown(
            f"<div class='card'><div class='title'>Общее количество потоков</div><div class='value'>{stats['t']}</div></div>",
            unsafe_allow_html=True
        )
        c2.markdown(
            f"<div class='card danger'><div class='title'>Количество обнаруженных угроз в потоках</div><div class='value'>{stats['a']}</div></div>",
            unsafe_allow_html=True
        )
        c3.markdown(
            f"<div class='card'><div class='title'>Количество нормальных потоков</div><div class='value'>{stats['b']}</div></div>",
            unsafe_allow_html=True
        )

        st.markdown("### Информация о нормальном трафике")
        st.dataframe(df[df["Anomaly"] != True], use_container_width=True, height=380)

        st.markdown("### Информация о трафике с аномалиями")
        st.dataframe(anomaly_df, use_container_width=True, height=380)

