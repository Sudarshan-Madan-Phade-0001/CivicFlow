import sqlite3
from datetime import datetime, timedelta

def create_test_request():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Create a pending request
    user_id = 4  # citizen user
    service_id = 471  # Aadhaar Services
    preferred_date = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    preferred_time = "10:00-11:00"
    
    c.execute('''INSERT INTO queue (user_id, service_id, preferred_date, preferred_time, status) 
                 VALUES (?, ?, ?, ?, ?)''', 
              (user_id, service_id, preferred_date, preferred_time, 'pending'))
    
    queue_id = c.lastrowid
    print(f"Created pending request with ID: {queue_id}")
    print(f"User ID: {user_id}, Service ID: {service_id}")
    print(f"Date: {preferred_date}, Time: {preferred_time}")
    print(f"Status: pending")
    
    conn.commit()
    conn.close()
    print("Test request created - should appear in admin dashboard!")

if __name__ == "__main__":
    create_test_request()