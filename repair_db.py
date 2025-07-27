#!/usr/bin/env python3
"""
Database Repair and Diagnostic Script
====================================
Use this script to diagnose and fix database issues with your PDF License Server.

Usage:
1. Add this file to your repository as `repair_db.py`
2. Set environment variable: DB_REPAIR_TOKEN=your-secret-token
3. Call the endpoint: POST /api/repair-db with Authorization header

Or run directly if you have database access:
python repair_db.py
"""

import os
import sys
import logging
import psycopg2
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - REPAIR - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_database_connection():
    """Get database connection"""
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        raise Exception("DATABASE_URL environment variable not set")
    
    # Fix postgres:// to postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    return psycopg2.connect(database_url, sslmode='require')

def diagnose_database():
    """Diagnose current database state"""
    logger.info("Starting database diagnosis...")
    
    try:
        conn = get_database_connection()
        conn.autocommit = True
        cur = conn.cursor()
        
        # Check database version
        cur.execute('SELECT version()')
        version = cur.fetchone()[0]
        logger.info(f"PostgreSQL Version: {version}")
        
        # Check current schema
        cur.execute("""
            SELECT schemaname, tablename 
            FROM pg_tables 
            WHERE schemaname = 'public'
            ORDER BY tablename
        """)
        tables = cur.fetchall()
        logger.info(f"Existing tables: {[table[1] for table in tables]}")
        
        # Check table structures
        for schema, table_name in tables:
            cur.execute("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = %s AND table_schema = %s
                ORDER BY ordinal_position
            """, (table_name, schema))
            columns = cur.fetchall()
            logger.info(f"Table {table_name} structure:")
            for col in columns:
                logger.info(f"  - {col[0]} ({col[1]}) {'NULL' if col[2] == 'YES' else 'NOT NULL'}")
        
        # Check indexes
        cur.execute("""
            SELECT schemaname, tablename, indexname, indexdef
            FROM pg_indexes 
            WHERE schemaname = 'public'
            ORDER BY tablename, indexname
        """)
        indexes = cur.fetchall()
        logger.info(f"Existing indexes:")
        for idx in indexes:
            logger.info(f"  - {idx[2]} on {idx[1]}")
        
        cur.close()
        conn.close()
        
        return {
            "status": "success",
            "tables": [table[1] for table in tables],
            "diagnosis": "Database diagnosis completed"
        }
        
    except Exception as e:
        logger.error(f"Database diagnosis failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

def repair_database():
    """Repair database by recreating tables"""
    logger.info("Starting database repair...")
    
    try:
        conn = get_database_connection()
        conn.autocommit = True
        cur = conn.cursor()
        
        # Drop existing tables if they exist (careful!)
        logger.info("Dropping existing tables...")
        cur.execute('DROP TABLE IF EXISTS validation_logs CASCADE')
        cur.execute('DROP TABLE IF EXISTS admin_sessions CASCADE') 
        cur.execute('DROP TABLE IF EXISTS licenses CASCADE')
        logger.info("Existing tables dropped")
        
        # Create licenses table
        logger.info("Creating licenses table...")
        cur.execute('''
            CREATE TABLE licenses (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                hardware_id VARCHAR(255),
                customer_email VARCHAR(255) NOT NULL,
                customer_name VARCHAR(255),
                created_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                payment_id VARCHAR(255),
                active BOOLEAN DEFAULT true,
                last_used TIMESTAMP WITH TIME ZONE,
                validation_count INTEGER DEFAULT 0,
                created_by VARCHAR(255) DEFAULT 'system'
            )
        ''')
        logger.info("✅ Licenses table created")
        
        # Create validation_logs table
        logger.info("Creating validation_logs table...")
        cur.execute('''
            CREATE TABLE validation_logs (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(255),
                hardware_id VARCHAR(255),
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                status VARCHAR(100),
                ip_address INET,
                user_agent TEXT,
                details JSONB
            )
        ''')
        logger.info("✅ Validation_logs table created")
        
        # Create admin_sessions table
        logger.info("Creating admin_sessions table...")
        cur.execute('''
            CREATE TABLE admin_sessions (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(255),
                username VARCHAR(255),
                ip_address INET,
                login_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        ''')
        logger.info("✅ Admin_sessions table created")
        
        # Create indexes
        logger.info("Creating indexes...")
        indexes = [
            ('idx_licenses_key', 'licenses', 'license_key'),
            ('idx_licenses_email', 'licenses', 'customer_email'),
            ('idx_licenses_expiry', 'licenses', 'expiry_date'),
            ('idx_licenses_active', 'licenses', 'active'),
            ('idx_validation_logs_timestamp', 'validation_logs', 'timestamp'),
            ('idx_validation_logs_license', 'validation_logs', 'license_key'),
            ('idx_validation_logs_status', 'validation_logs', 'status')
        ]
        
        for index_name, table_name, column_name in indexes:
            try:
                cur.execute(f'CREATE INDEX {index_name} ON {table_name}({column_name})')
                logger.info(f"✅ Created index {index_name}")
            except Exception as e:
                logger.warning(f"⚠️ Could not create index {index_name}: {e}")
        
        # Verify repair by checking table structure
        logger.info("Verifying repair...")
        for table_name in ['licenses', 'validation_logs', 'admin_sessions']:
            cur.execute("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = %s AND table_schema = 'public'
                ORDER BY ordinal_position
            """, (table_name,))
            columns = [row[0] for row in cur.fetchall()]
            logger.info(f"✅ Table {table_name} has columns: {columns}")
        
        cur.close()
        conn.close()
        
        logger.info("🎉 Database repair completed successfully!")
        
        return {
            "status": "success", 
            "message": "Database repaired successfully",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database repair failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def create_sample_data():
    """Create some sample data for testing"""
    logger.info("Creating sample data...")
    
    try:
        conn = get_database_connection()
        conn.autocommit = True
        cur = conn.cursor()
        
        # Insert sample license
        cur.execute('''
            INSERT INTO licenses (license_key, customer_email, customer_name, expiry_date, created_by)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (license_key) DO NOTHING
        ''', (
            'PDFM-TEST-1234-5678',
            'test@example.com', 
            'Test User',
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'repair_script'
        ))
        
        logger.info("✅ Sample license created")
        
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Sample data created"}
        
    except Exception as e:
        logger.error(f"Sample data creation failed: {e}")
        return {"status": "error", "error": str(e)}

if __name__ == '__main__':
    print("🔧 PDF License Server Database Repair Tool")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'diagnose':
            result = diagnose_database()
            print(f"Diagnosis result: {result}")
            
        elif command == 'repair':
            result = repair_database()
            print(f"Repair result: {result}")
            
        elif command == 'sample':
            result = create_sample_data()
            print(f"Sample data result: {result}")
            
        else:
            print("Usage: python repair_db.py [diagnose|repair|sample]")
    else:
        print("Available commands:")
        print("  python repair_db.py diagnose  - Check current database state")
        print("  python repair_db.py repair    - Fix database tables and indexes")
        print("  python repair_db.py sample    - Create sample test data")
        print()
        print("Or use the API endpoints in your Flask app:")
        print("  POST /api/repair-db (with Authorization header)")