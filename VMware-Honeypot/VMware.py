# --- Imports ---
import base64
from flask import Flask, request, render_template, jsonify, redirect, send_file # Thêm send_file
import logging
import json
from datetime import datetime

# Imports cho phần phân tích/báo cáo
import re
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import pandas as pd
import sys
import ast

# Imports cho việc chạy nền định kỳ
import schedule # Cần cài: pip install schedule
import time
import threading

# --- Cấu hình Honeypot ---
app = Flask(__name__)

# Tên file log và báo cáo
log_file = 'honeypot.log'
output_excel = "honeypot_report.xlsx"
output_html = "honeypot_report.html"
output_plot = "top_ips.png" # Tên file biểu đồ
time_format_log = "%Y-%m-%d %H:%M:%S"
threshold = 5  # Ngưỡng cảnh báo

# Cấu hình logging
logger = logging.getLogger('honeypot_logger')
logger.setLevel(logging.INFO)
if not logger.handlers:
    file_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

# Hàm ghi log
def log_attempt(endpoint, method, data=None, ip=None, user_agent=None):
    log_entry = {
        'timestamp': datetime.utcnow().strftime(time_format_log), # Sử dụng định dạng từ cấu hình
        'endpoint': endpoint,
        'method': method,
        'ip': ip or request.remote_addr,
        'user_agent': user_agent or request.headers.get('User-Agent'),
    }
    if data is not None:
         if hasattr(data, 'to_dict'):
             log_entry['data'] = data.to_dict()
         else:
             log_entry['data'] = data

    logger.info('Attempt Detected: %s', log_entry)

# Redirect root to the VMware UI
@app.route('/', methods=['GET'])
def redirect_to_vmware_ui():
    return redirect('/ui/', code=302)

# Simulate VMware HTTPS service on port 443
@app.route('/ui/', methods=['GET', 'POST'])
def vsphere_ui():
    if request.method == 'POST':
        log_attempt('/ui/', 'POST', request.form)
        return jsonify({'message': 'Login failed', 'error': 'Invalid credentials'}), 401
    else:
        log_attempt('/ui/', 'GET')
        try:
            return render_template('dummy_vsphere_login.html')
        except Exception as e:
            logger.error(f"Error rendering template: {e}")
            return "Error loading login page.", 500


# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    log_attempt(request.path, request.method)
    return jsonify({'message': 'Service not found'}), 404

# --- Kết thúc phần Honeypot ---


# --- Phần Phân tích và Báo cáo ---

def generate_report():
    """
    # Đọc file log, phân tích và tạo báo cáo tĩnh (Excel, HTML, PNG).
    """
    print(f"[REPORT] Đang đọc file log: {log_file}")

    endpoint_count = defaultdict(int)
    ip_counter = Counter()
    user_agents = Counter()
    ip_times = defaultdict(list)
    entries = []
    parse_errors = 0
    collected_credentials = []

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                match = re.search(r"Attempt Detected: (.+)", line)
                if match:
                    try:
                        log_data_str = match.group(1)
                        data = ast.literal_eval(log_data_str) # Sử dụng ast.literal_eval

                        ts_str = data.get("timestamp")
                        if not ts_str:
                             raise ValueError("Thiếu timestamp trong log entry")
                        ts = datetime.strptime(ts_str, time_format_log)

                        ip = data.get("ip", "unknown")
                        ep = data.get("endpoint", "unknown")
                        method = data.get("method", "unknown")
                        ua = data.get("user_agent", "unknown")
                        form_data = data.get("data")

                        # Đếm
                        endpoint_count[ep] += 1
                        ip_counter[ip] += 1
                        user_agents[ua] += 1
                        ip_times[ip].append(ts)

                        # Thu thập username và password nếu có
                        if ep == '/ui/' and method == 'POST' and isinstance(form_data, dict):
                             attempted_username = form_data.get('username')
                             attempted_password = form_data.get('password')

                             if attempted_username is not None or attempted_password is not None:
                                  collected_credentials.append({
                                       "timestamp": ts,
                                       "ip": ip,
                                       "user_agent": ua,
                                       "username": attempted_username if attempted_username is not None else "",
                                       "password": attempted_password if attempted_password is not None else ""
                                  })

                        # Lưu entry chi tiết
                        entries.append({
                            "timestamp": ts,
                            "ip": ip,
                            "method": method,
                            "endpoint": ep,
                            "user_agent": ua,
                            "data": form_data
                        })

                    except Exception as e:
                        parse_errors += 1
                        # print(f"Lỗi parse dòng log {i+1}: {line.strip()} - Chi tiết: {e}")
                        pass

    except FileNotFoundError:
        print(f"[REPORT] ❌ Lỗi: Không tìm thấy file log '{log_file}'. Bỏ qua tạo báo cáo lần này.")
        return # Thoát hàm nếu không có log file
    except Exception as e:
         print(f"[REPORT] ❌ Lỗi khi đọc hoặc xử lý file log: {e}")
         return # Thoát hàm nếu gặp lỗi

    print(f"[REPORT] Đọc file log hoàn tất. Số dòng log parse lỗi: {parse_errors}")
    print("[REPORT] Đang phân tích dữ liệu...")

    # ========== CẢNH BÁO ==========
    alerts = []
    potential_attackers = [ip for ip, count in ip_counter.items() if count > threshold]

    for ip in potential_attackers:
         times = sorted(ip_times[ip])
         for i in range(len(times)):
             count = sum(1 for t in times if 0 <= (t - times[i]).total_seconds() <= 300)
             if count > threshold:
                 alerts.append((ip, count, times[i].strftime(time_format_log)))
                 break

    print(f"[REPORT] Tìm thấy {len(alerts)} cảnh báo IP đáng ngờ.")
    print(f"[REPORT] Thu thập được {len(collected_credentials)} bộ thông tin đăng nhập.")

    # ========== BIỂU ĐỒ ==========
    print("[REPORT] Đang tạo biểu đồ Top IP...")
    if ip_counter:
        top_ips = ip_counter.most_common(10)
        ips = [ip for ip, _ in top_ips]
        counts = [count for _, count in top_ips]

        plt.figure(figsize=(10, 6))
        plt.bar(ips, counts, color='orange')
        plt.title("Top 5 IP tấn công")
        plt.xlabel("IP")
        plt.ylabel("Số lần truy cập")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        try:
            plt.savefig(output_plot) # Lưu biểu đồ với tên output_plot
            print(f"[REPORT] ✅ Lưu biểu đồ tại: {output_plot}")
        except Exception as e:
             print(f"[REPORT] ❌ Lỗi khi lưu biểu đồ: {e}")
        plt.close()
    else:
        print("[REPORT] ⚠️ Không có dữ liệu IP để vẽ biểu đồ.")

    # ========== XUẤT FILE ==========
    print("[REPORT] Đang tạo báo cáo Excel và HTML...")

    # Báo cáo chi tiết toàn bộ log
    if entries:
        df_entries = pd.DataFrame(entries)
        df_entries["timestamp"] = pd.to_datetime(df_entries["timestamp"])
        df_entries = df_entries.sort_values(by="timestamp")

        # Excel
        try:
            with pd.ExcelWriter(output_excel) as writer:
                 df_entries.to_excel(writer, sheet_name='Log Chi Tiet', index=False)
                 if collected_credentials:
                      df_credentials = pd.DataFrame(collected_credentials)
                      df_credentials = df_credentials.sort_values(by="timestamp")
                      df_credentials.to_excel(writer, sheet_name='Tai Khoan Thu Thap', index=False)
                 else:
                       pd.DataFrame([{"message": "Không có thông tin đăng nhập nào được thu thập"}]).to_excel(writer, sheet_name='Tai Khoan Thu Thap', index=False)

            print(f"[REPORT] ✅ Lưu báo cáo Excel tại: {output_excel}")
        except Exception as e:
             print(f"[REPORT] ❌ Lỗi khi lưu file Excel: {e}")
             logger.error(f"Lỗi chi tiết khi lưu file Excel: {e}")


    else:
        print("[REPORT] ⚠️ Không có dữ liệu log hợp lệ để tạo báo cáo chi tiết (Excel).")


    # HTML Report
    try:
        with open(output_html, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html><html><head><title>Báo cáo Honeypot</title><meta charset='utf-8'><style>table {border-collapse: collapse; width: 100%;} th, td {border: 1px solid #ddd; padding: 8px;} th {background-color: #f2f2f2; text-align: left;} tr:nth-child(even) {background-color: #f9f9f9;} body {font-family: Arial, sans-serif; margin: 20px;}</style></head><body>") # Thêm margin
            f.write("<h1>Báo cáo Honeypot</h1>")
            f.write(f"<p>Thời gian tạo báo cáo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>") # Thêm thời gian tạo báo cáo

            f.write("<h2>1. Thống kê chung</h2>")
            f.write("<h3>Top 5 IP tấn công</h3><ul>")
            if ip_counter:
                for ip, count in ip_counter.most_common(5):
                    f.write(f"<li><b>{ip}</b>: {count} lần</li>")
            else: f.write("<li>Chưa có dữ liệu IP.</li>")
            f.write("</ul>")

            f.write("<h3>Top 5 Endpoint bị truy cập</h3><ul>")
            if endpoint_count:
                for ep, count in Counter(endpoint_count).most_common(5):
                     f.write(f"<li><b>{ep}</b>: {count} lần</li>")
            else: f.write("<li>Chưa có dữ liệu Endpoint.</li>")
            f.write("</ul>")

            f.write("<h3>Top 5 User Agent</h3><ul>")
            if user_agents:
                for ua, count in user_agents.most_common(5):
                     f.write(f"<li><b>{ua}</b>: {count} lần</li>")
            else: f.write("<li>Chưa có dữ liệu User Agent.</li>")
            f.write("</ul>")

            # Chèn biểu đồ vào HTML
            try:
                with open(output_plot, "rb") as img_file:
                    img_base64 = base64.b64encode(img_file.read()).decode('utf-8')
                    f.write("<h2>Biểu đồ Top IP</h2>")
                    f.write(f'<img src="data:image/png;base64,{img_base64}" alt="Top IPs Chart">')
            except FileNotFoundError:
                f.write("<h2>Biểu đồ Top IP</h2><p>Chưa có biểu đồ (có thể do chưa có dữ liệu hoặc lỗi khi tạo biểu đồ).</p>")
            except Exception as e:
                 f.write(f"<h2>Biểu đồ Top IP</h2><p>Lỗi khi chèn biểu đồ: {e}</p>")
                 logger.error(f"Lỗi chi tiết khi chèn biểu đồ vào HTML: {e}")


            f.write("<h2>2. Cảnh báo IP đáng ngờ</h2>")
            if alerts:
                f.write(f"<p>Các IP có hoạt động vượt ngưỡng (>{threshold} lần) trong vòng 5 phút:</p><ul>")
                for ip, count, time_str in alerts: # Đổi tên biến time để không trùng với module time
                    f.write(f"<li>⚠️ <b>{ip}</b>: {count} lần trong 5 phút (bắt đầu khoảng từ {time_str})</li>")
                f.write("</ul>")
            else:
                f.write(f"<p>Không có cảnh báo IP đáng ngờ nào được phát hiện dựa trên ngưỡng {threshold} lần trong 5 phút.</p>")


            # Báo cáo thông tin đăng nhập thu thập được
            f.write("<h2>3. Thông tin đăng nhập thu thập được</h2>")
            if collected_credentials:
                df_credentials = pd.DataFrame(collected_credentials)
                df_credentials = df_credentials.sort_values(by="timestamp")
                df_credentials = df_credentials.dropna(axis=1, how='all')
                f.write(df_credentials.to_html(index=False, classes='table table-striped'))
            else:
                f.write("<p>Không có thông tin đăng nhập nào được thu thập từ các lần thử.</p>")


            f.write("<h2>4. Log chi tiết</h2>")
            if entries:
                 df_entries = pd.DataFrame(entries) # Tạo lại DataFrame từ entries mới nhất
                 df_entries["timestamp"] = pd.to_datetime(df_entries["timestamp"])
                 df_entries = df_entries.sort_values(by="timestamp")

                 max_html_rows = 200
                 if len(df_entries) > max_html_rows:
                     f.write(f"<p>Hiển thị {max_html_rows} dòng log cuối cùng (Tổng cộng có {len(df_entries)} dòng log).</p>") # Thường xem log cuối cùng quan trọng hơn
                     f.write(df_entries.tail(max_html_rows).to_html(index=False, classes='table table-striped')) # Hiển thị tail
                 else:
                    f.write(df_entries.to_html(index=False, classes='table table-striped'))
            else:
                 f.write("<p>Không có dữ liệu log chi tiết để hiển thị.</p>")


            f.write("</body></html>")
        print(f"[REPORT] ✅ Lưu báo cáo HTML tại: {output_html}")
    except Exception as e:
        print(f"[REPORT] ❌ Lỗi khi lưu file HTML: {e}")
        logger.error(f"Lỗi chi tiết khi lưu file HTML: {e}")


    print(f"[REPORT] ✅ Phân tích hoàn tất!")

# --- Phần Chạy Nền Lên Lịch ---

def run_schedule():
    """
    Hàm chạy vòng lặp schedule trong một luồng riêng.
    """
    while True:
        schedule.run_pending()
        time.sleep(1) # Kiểm tra mỗi giây

# Tạo một luồng cho scheduler
scheduler_thread = threading.Thread(target=run_schedule)
scheduler_thread.daemon = True # Cho phép chương trình chính thoát ngay cả khi luồng này đang chạy

# Lên lịch tạo báo cáo - ví dụ mỗi 5 phút
schedule.every(5).minutes.do(generate_report)
print("[SCHEDULER] Lên lịch tạo báo cáo mỗi 5 phút.")


# --- Route phục vụ báo cáo HTML tĩnh ---
@app.route('/report') # Bạn có thể chọn URL khác, ví dụ /honeypot_report
def serve_report():
    try:
        # Trả về file HTML
        return send_file(output_html)
    except FileNotFoundError:
        return "Báo cáo chưa được tạo hoặc không tìm thấy file.", 404
    except Exception as e:
        logger.error(f"Error serving report file: {e}")
        return "Đã xảy ra lỗi khi phục vụ báo cáo.", 500


# --- Logic chạy chính ---
if __name__ == '__main__':
    # Khi chạy script trực tiếp
    if len(sys.argv) > 1 and sys.argv[1] == 'report':
        # Chế độ chỉ tạo báo cáo (một lần và thoát)
        print("Chạy ở chế độ tạo báo cáo một lần.")
        generate_report()
    else:
        # Chế độ chạy Honeypot + Chạy Nền Tạo Báo cáo

        # Chạy generate_report() lần đầu tiên khi khởi động để có báo cáo ban đầu ngay
        generate_report()

        # Bắt đầu luồng chạy scheduler
        scheduler_thread.start()
        print("[SCHEDULER] Luồng scheduler đã bắt đầu.")

        print(f"Starting honeypot Flask server. Logging to {log_file}")
        print("Access honeypot via http://<Your_IP_Address>:5000")
        print("Access report via http://<Your_IP_Address>:5000/report")
        print("To generate a report manually, run: python your_script_name.py report")


        # Sử dụng Waitress cho production
        try:
             from waitress import serve # type: ignore
             print("Using Waitress WSGI server.")
             serve(app, host='0.0.0.0', port=5000)
        except ImportError:
             print("Waitress not found. Running with Flask built-in server (NOT recommended for production).")
             # Chạy debug=False khi không có Waitress trong production
             app.run(host='0.0.0.0', port=5000, debug=False)