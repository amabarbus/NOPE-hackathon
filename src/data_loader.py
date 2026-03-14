import csv
import os
from src.database import get_db_connection

def load_kaggle_to_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if we've already loaded data
    cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE is_live = 0')
    if cursor.fetchone()[0] > 0:
        print("✅ Kaggle data already in database. Skipping import.")
        conn.close()
        return

    try:
        csv_path = os.path.join(os.path.dirname(__file__), '..', 'cybersecurity_attacks.csv')
        
        with open(csv_path, mode='r', encoding='utf-8-sig') as file:
            csv_reader = csv.DictReader(file, quoting=csv.QUOTE_NONE)
            
            logs_to_insert = []
            for i, row in enumerate(csv_reader):
                if i >= 1000: break
                
                timestamp = row.get('Timestamp', '')
                if not timestamp: continue
                
                parts = timestamp.split(' ')
                date = parts[0]
                time_val = parts[1] if len(parts) > 1 else "00:00:00"
                
                sev_raw = str(row.get('Severity Level', 'Low')).upper()
                badge = "[CRITICAL]" if "HIGH" in sev_raw or "CRITICAL" in sev_raw else "[WARNING]" if "MEDIUM" in sev_raw else "[INFO]"
                
                logs_to_insert.append((
                    date, time_val, badge, row.get('Attack Type', 'Threat'),
                    row.get('Source IP Address', '0.0.0.0'),
                    str(row.get('Payload Data', ''))[:100],
                    row.get('Geo-location Data', 'Unknown'),
                    0 # is_live = False
                ))

            cursor.executemany('''
                INSERT INTO attack_logs (date, time, severity, attack_type, source_ip, payload, source_location, is_live)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', logs_to_insert)
            
            conn.commit()
            print(f"✅ Imported {len(logs_to_insert)} Kaggle attacks into SQLite.")
            
    except Exception as e:
        print(f"⚠️ CSV Import Error: {e}")
    finally:
        conn.close()
