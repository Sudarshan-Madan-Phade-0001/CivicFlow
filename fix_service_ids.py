import sqlite3

def fix_service_ids():
    conn = sqlite3.connect('civic_flow.db')
    c = conn.cursor()
    
    # Get current valid service IDs
    c.execute('SELECT id FROM services ORDER BY id ASC')
    valid_ids = [row[0] for row in c.fetchall()]
    print(f"Valid service IDs: {valid_ids}")
    
    # Update all queue items to use first valid service ID
    if valid_ids:
        first_service_id = valid_ids[0]
        c.execute('UPDATE queue SET service_id = ?', (first_service_id,))
        print(f"Updated all queue items to service_id: {first_service_id}")
    
    conn.commit()
    conn.close()
    print("Service IDs fixed!")

if __name__ == "__main__":
    fix_service_ids()