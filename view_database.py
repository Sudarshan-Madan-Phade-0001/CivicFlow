import sqlite3
import pandas as pd

def view_database():
    conn = sqlite3.connect('civic_flow.db')
    
    print("=== USERS TABLE ===")
    users = pd.read_sql_query("SELECT * FROM users", conn)
    print(users)
    
    print("\n=== SERVICES TABLE ===")
    services = pd.read_sql_query("SELECT * FROM services", conn)
    print(services)
    
    print("\n=== QUEUE TABLE ===")
    queue = pd.read_sql_query("SELECT * FROM queue", conn)
    print(queue)
    
    conn.close()

if __name__ == "__main__":
    view_database()