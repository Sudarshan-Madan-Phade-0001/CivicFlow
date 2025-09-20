import sqlite3
import random
import string

def fix_queue_data():
    print("Fixing queue data...")
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Get valid service IDs
    c.execute('SELECT id, name FROM services')
    services = c.fetchall()
    print("Valid services:", services)
    
    # Fix invalid service_ids in queue
    valid_service_ids = [s[0] for s in services]
    
    c.execute('SELECT id, service_id FROM queue')
    queue_items = c.fetchall()
    
    for queue_id, service_id in queue_items:
        if service_id not in valid_service_ids:
            # Assign to first service (Aadhaar)
            new_service_id = valid_service_ids[0]
            c.execute('UPDATE queue SET service_id = ? WHERE id = ?', (new_service_id, queue_id))
            print(f"Fixed queue {queue_id}: {service_id} -> {new_service_id}")
    
    # Add validation tokens to all requests without tokens
    c.execute('SELECT id FROM queue WHERE validation_token IS NULL')
    pending = c.fetchall()
    
    for queue_id, in pending:
        validation_token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        queue_number = random.randint(1, 100)
        c.execute('UPDATE queue SET status = "waiting", queue_number = ?, validation_token = ? WHERE id = ?', 
                  (queue_number, validation_token, queue_id))
        print(f"Approved queue {queue_id} with token {validation_token}")
    
    conn.commit()
    conn.close()
    print("Database fixed!")

if __name__ == "__main__":
    fix_queue_data()