import sqlite3
import random
import string
from datetime import datetime, timedelta

def create_test_request():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Create a test request
    user_id = 4  # citizen user
    service_id = 441  # Aadhaar Services
    preferred_date = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
    preferred_time = "09:00-10:00"
    
    c.execute('''INSERT INTO queue (user_id, service_id, preferred_date, preferred_time, status) 
                 VALUES (?, ?, ?, ?, ?)''', 
              (user_id, service_id, preferred_date, preferred_time, 'pending'))
    
    queue_id = c.lastrowid
    print(f"Created test request with ID: {queue_id}")
    
    # Now approve it (simulate admin approval)
    queue_number = 1
    validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    c.execute('''UPDATE queue SET status = ?, queue_number = ?, validation_token = ? 
                 WHERE id = ?''', 
              ('waiting', queue_number, validation_token, queue_id))
    
    print(f"Approved request - Token: {queue_number}, Validation: {validation_token}")
    
    conn.commit()
    conn.close()
    print("Test request created and approved!")

if __name__ == "__main__":
    create_test_request()