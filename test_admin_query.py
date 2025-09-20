import sqlite3

def test_admin_query():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    print("Testing admin dashboard query...")
    
    # Test the exact query from admin dashboard
    c.execute('''SELECT q.id, q.queue_number, s.name, u.username, q.created_at, q.status, q.preferred_date, q.preferred_time
                 FROM queue q 
                 JOIN services s ON q.service_id = s.id 
                 JOIN users u ON q.user_id = u.id 
                 WHERE q.status = "pending"
                 ORDER BY q.created_at ASC''')
    
    pending_requests = c.fetchall()
    
    print(f"Found {len(pending_requests)} pending requests:")
    for req in pending_requests:
        print(f"ID: {req[0]}, Service: {req[2]}, User: {req[3]}, Date: {req[6]}, Time: {req[7]}")
    
    conn.close()

if __name__ == "__main__":
    test_admin_query()