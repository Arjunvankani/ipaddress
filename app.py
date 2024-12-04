import streamlit as st
import pandas as pd
import re
from collections import defaultdict
import matplotlib.pyplot as plt
import plotly.express as px
import requests
from io import StringIO
import socket  
import time  
import os  

st.title('Log File Analysis with Graphical Insights')
sidebar_options = st.sidebar.radio("Choose an option", ["Home", "Advanced"])

# log file
def process_log_file(file):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    # regex to extract IP addresses, endpoints, and login failures
    log_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] ".*? (\/\S*) .*" (\d+)')
    login_fail_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] ".*?POST.*? /login .*" 401')

    for line in file:
        line = line.decode('utf-8')  
        match = log_regex.search(line)
        if match:
            ip, endpoint, status_code = match.groups()
            ip_requests[ip] += 1
            endpoint_requests[endpoint] += 1

        # Detect failed login attempts
        if "Invalid credentials" in line or "401" in line:
            failed_login_match = login_fail_regex.search(line)
            if failed_login_match:
                ip_failed = failed_login_match.group(1)
                failed_logins[ip_failed] += 1

    return ip_requests, endpoint_requests, failed_logins

def process_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            log_file = StringIO(response.text)
            return process_log_file(log_file)
        else:
            st.error("Failed to download the log file. Check the URL and try again.")
    except Exception as e:
        st.error(f"An error occurred while fetching the URL: {str(e)}")

# Home - Upload a log file
if sidebar_options == "Home":
    st.subheader("Log File Upload and Analysis")
    uploaded_file = st.file_uploader("Upload a log file", type=["log"])

    if uploaded_file is not None:
        st.subheader('Analyzing the log file...')

        ip_requests, endpoint_requests, failed_logins = process_log_file(uploaded_file)
        
        # 1. Count Requests per IP Address
        st.subheader('Request Count per IP Address')
        ip_data = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
        ip_df = pd.DataFrame(ip_data, columns=["IP Address", "Request Count"])
        st.dataframe(ip_df)

        # Option to choose colors for the bar chart
        st.subheader("Bar Chart of Request Counts per IP Address")
        color_options = st.multiselect('Choose bar colors', 
                                       ['skyblue', 'salmon', 'green', 'orange', 'purple', 'yellow'], 
                                       default=['skyblue'])

        # Show the bar chart with multi-color feature
        fig, ax = plt.subplots()
        ip_df.plot(kind='bar', x='IP Address', y='Request Count', ax=ax, color=color_options * len(ip_df))
        ax.set_xlabel('IP Address')
        ax.set_ylabel('Request Count')
        ax.set_title('Request Count per IP Address')
        ax.legend().remove()  
        plt.xticks(rotation=45, ha='right') 
        st.pyplot(fig)

        # 2. Most Frequently Accessed Endpoint
        st.subheader('Most Frequently Accessed Endpoint')
        most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
        st.write(f"**Most Accessed Endpoint**: `{most_accessed_endpoint[0]}` accessed {most_accessed_endpoint[1]} times")

        # Pie chart for endpoint access frequency
        st.subheader("Endpoint Access Frequency - Pie Chart")
        endpoint_data = sorted(endpoint_requests.items(), key=lambda x: x[1], reverse=True)
        endpoint_df = pd.DataFrame(endpoint_data, columns=["Endpoint", "Access Count"])
        fig_pie = px.pie(endpoint_df, names="Endpoint", values="Access Count", title="Endpoint Access Frequency")
        st.plotly_chart(fig_pie)

        # 3. Detect Suspicious Activity (failed login attempts)
        st.subheader('Suspicious Activity - Failed Login Attempts')
        failed_login_threshold = st.slider('Failed login attempt threshold', min_value=1, max_value=100, value=10)
        suspicious_ips = [(ip, count) for ip, count in failed_logins.items() if count >= failed_login_threshold]
        suspicious_ips_df = pd.DataFrame(suspicious_ips, columns=["IP Address", "Failed Login Count"])
        st.dataframe(suspicious_ips_df)
        st.subheader("Histogram of Failed Login Attempts by IP")
        hist_color = st.color_picker('Pick a color for the histogram', '#ff6347')  

        if not suspicious_ips_df.empty:
            fig_fail, ax_fail = plt.subplots()
            ax_fail.bar(suspicious_ips_df["IP Address"], suspicious_ips_df["Failed Login Count"], color=hist_color)
            ax_fail.set_xlabel('IP Address')
            ax_fail.set_ylabel('Failed Login Count')
            ax_fail.set_title('Failed Login Attempts per IP Address')
            plt.xticks(rotation=45, ha='right') 
            st.pyplot(fig_fail)
        else:
            st.write("No suspicious IPs found exceeding the threshold.")

        save_results = st.checkbox("Save results to CSV")
        
        if save_results:
            log_analysis_results = {
                'Requests per IP': ip_df,
                'Most Accessed Endpoint': pd.DataFrame([[most_accessed_endpoint[0], most_accessed_endpoint[1]]], 
                                                        columns=["Endpoint", "Access Count"]),
                'Suspicious Activity': suspicious_ips_df
            }

            for key, df in log_analysis_results.items():
                df.to_csv(f'{key.lower().replace(" ", "_")}_results.csv', index=False)
                st.write(f"Results for {key} saved as CSV.")
                
# create log from website request
def create_log_from_url(website_url):
    log_data = ""
    try:
        ip_address = socket.gethostbyname(website_url)
        st.write("Sending requests...")
        progress_bar = st.progress(0)
        
        for i in range(1, 6):  
            time.sleep(1)  
            response = requests.get(f"http://{website_url}")
            status_code = response.status_code
            log_data += f"{ip_address} - - [Request {i}] \"GET / {status_code}\" {status_code}\n"
            progress_bar.progress(i * 20)  

        st.write("All requests sent!")
        return log_data
    except Exception as e:
        st.error(f"Error occurred: {e}")
        return None

if 'generated_logs' not in st.session_state:
    st.session_state.generated_logs = []

if sidebar_options == "Advanced":
    st.subheader("Advanced Feature: Generate Log from Website")

    website_url = st.text_input("Enter Website Link (without http/https)")

    if website_url:
        if st.button("Start Request"):
            log_data = create_log_from_url(website_url)
            
            if log_data:
                sample_log_path = os.path.join("sample.log")
                with open(sample_log_path, "w") as log_file:
                    log_file.write(log_data)

                st.success("Log generated successfully!")
                st.download_button("Download Log File", data=log_data, file_name="sample.log", mime="text/plain")
                st.text(log_data)
                     
