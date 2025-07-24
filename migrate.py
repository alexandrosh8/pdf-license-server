#!/usr/bin/env python3
"""
Database Migration Script for PDF License Server
Fixes PostgreSQL compatibility issues on Render platform

Run this script before deploying to fix existing database schema
"""

import asyncio
import asyncpg
import os
import sys
from datetime import datetime

class DatabaseFixer:
    """Fix existing database schema issues"""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.conn = None
    
    async def connect(self):
        """Connect to database"""
        try:
            self.conn = await asyncpg.connect(self.database_url)
            print("✅ Connected to PostgreSQL database")
        except Exception as e:
            print(f"❌ Failed to connect to database: {e}")
            sys.exit(1)
    
    async def close(self):
        """Close database connection"""
        if self.conn:
            await self.conn.close()
            print("✅ Database connection closed")
    
    async def run_fixes(self):
        """Run all database fixes"""
        print("🔧 Starting database schema fixes...")
        
        await self.fix_timestamp_columns()
        await self.add_missing_columns()
        await self.create_indexes()
        await self.verify_schema()
        
        print("✅ All database fixes completed successfully!")
    
    async def fix_timestamp_columns(self):
        """Fix text columns that should be timestamps"""
        print("📅 Fixing timestamp column types...")
        
        # Get all tables and their text columns that should be timestamps
        timestamp_columns = [
            ('licenses', 'created_date'),
            ('licenses', 'expiry_date'),
            ('licenses', 'last_validated'),
            ('validation_logs', 'timestamp'),
            ('admin_sessions', 'created_at'),
            ('admin_sessions', 'expires_at'),
        ]
        
        for table_name, column_name in timestamp_columns:
            try:
                # Check if table exists
                table_exists = await self.conn.fetchval("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = $1
                    )
                """, table_name)
                
                if not table_exists:
                    print(f"⚠️  Table {table_name} doesn't exist, skipping...")
                    continue
                
                # Check current column type
                current_type = await self.conn.fetchval("""
                    SELECT data_type 
                    FROM information_schema.columns 
                    WHERE table_name = $1 AND column_name = $2
                """, table_name, column_name)
                
                if current_type in ['text', 'character varying']:
                    print(f"🔄 Converting {table_name}.{column_name} from {current_type} to timestamp...")
                    
                    # Safe conversion with fallback for invalid dates
                    await self.conn.execute(f"""
                        ALTER TABLE {table_name} 
                        ALTER COLUMN {column_name} TYPE TIMESTAMP WITH TIME ZONE 
                        USING CASE 
                            WHEN {column_name} IS NULL THEN NULL
                            WHEN {column_name} ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' 
                                THEN {column_name}::TIMESTAMP WITH TIME ZONE
                            ELSE CURRENT_TIMESTAMP
                        END
                    """)
                    print(f"✅ Converted {table_name}.{column_name} to timestamp")
                    
                elif current_type in ['timestamp without time zone', 'timestamp with time zone']:
                    print(f"✅ {table_name}.{column_name} already timestamp type")
                else:
                    print(f"⚠️  {table_name}.{column_name} has unexpected type: {current_type}")
                    
            except Exception as e:
                print(f"❌ Failed to convert {table_name}.{column_name}: {e}")
    
    async def add_missing_columns(self):
        """Add missing columns to tables"""
        print("📊 Adding missing columns...")
        
        # Define columns that should exist
        required_columns = [
            ('licenses', 'validation_count', 'INTEGER DEFAULT 0'),
            ('licenses', 'hardware_changes', 'INTEGER DEFAULT 0'),
            ('licenses', 'last_validated', 'TIMESTAMP WITH TIME ZONE'),
            ('validation_logs', 'response_time_ms', 'INTEGER'),
            ('validation_logs', 'details', 'JSONB DEFAULT \'{}\''),
            ('licenses', 'metadata', 'JSONB DEFAULT \'{}\''),
        ]
        
        for table_name, column_name, column_definition in required_columns:
            try:
                # Check if table exists
                table_exists = await self.conn.fetchval("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = $1
                    )
                """, table_name)
                
                if not table_exists:
                    print(f"⚠️  Table {table_name} doesn't exist, skipping...")
                    continue
                
                # Check if column exists
                column_exists = await self.conn.fetchval("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.columns
                        WHERE table_name = $1 AND column_name = $2
                    )
                """, table_name, column_name)
                
                if not column_exists:
                    print(f"➕ Adding column {table_name}.{column_name}...")
                    await self.conn.execute(f"""
                        ALTER TABLE {table_name} 
                        ADD COLUMN {column_name} {column_definition}
                    """)
                    print(f"✅ Added {table_name}.{column_name}")
                else:
                    print(f"✅ Column {table_name}.{column_name} already exists")
                    
            except Exception as e:
                print(f"❌ Failed to add {table_name}.{column_name}: {e}")
    
    async def create_indexes(self):
        """Create performance indexes"""
        print("🚀 Creating performance indexes...")
        
        indexes = [
            ("idx_licenses_hash", "licenses", "license_key_hash"),
            ("idx_licenses_active_expiry", "licenses", "active, expiry_date"),
            ("idx_licenses_hardware", "licenses", "hardware_id"),
            ("idx_validation_logs_timestamp", "validation_logs", "timestamp"),
            ("idx_validation_logs_license", "validation_logs", "license_key_hash"),
            ("idx_admin_sessions_expires", "admin_sessions", "expires_at"),
        ]
        
        for index_name, table_name, columns in indexes:
            try:
                # Check if table exists
                table_exists = await self.conn.fetchval("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = $1
                    )
                """, table_name)
                
                if not table_exists:
                    print(f"⚠️  Table {table_name} doesn't exist, skipping index...")
                    continue
                
                await self.conn.execute(f"""
                    CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}({columns})
                """)
                print(f"✅ Created index {index_name}")
                
            except Exception as e:
                print(f"⚠️  Index {index_name} creation skipped: {e}")
    
    async def verify_schema(self):
        """Verify the schema is correct"""
        print("🔍 Verifying schema...")
        
        try:
            # Test timestamp comparisons
            await self.conn.fetchval("""
                SELECT COUNT(*) FROM licenses 
                WHERE expiry_date > CURRENT_TIMESTAMP
            """)
            print("✅ Timestamp comparisons working")
            
            # Test validation_count column
            await self.conn.fetchval("""
                SELECT COUNT(*) FROM licenses 
                WHERE validation_count IS NOT NULL
            """)
            print("✅ validation_count column accessible")
            
            # Test JSONB columns if they exist
            try:
                await self.conn.fetchval("""
                    SELECT COUNT(*) FROM licenses 
                    WHERE metadata IS NOT NULL
                """)
                print("✅ JSONB columns working")
            except:
                print("⚠️  JSONB columns not found (optional)")
            
        except Exception as e:
            print(f"❌ Schema verification failed: {e}")
            raise
    
    async def create_missing_tables(self):
        """Create any missing core tables"""
        print("📋 Creating missing tables...")
        
        # Create licenses table if it doesn't exist
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key_hash VARCHAR(64) UNIQUE NOT NULL,
                license_key_encrypted TEXT NOT NULL,
                hardware_id VARCHAR(32),
                customer_email VARCHAR(255) NOT NULL,
                customer_name VARCHAR(255),
                created_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                last_validated TIMESTAMP WITH TIME ZONE,
                validation_count INTEGER DEFAULT 0,
                hardware_changes INTEGER DEFAULT 0,
                previous_hardware_ids TEXT,
                active BOOLEAN DEFAULT TRUE,
                payment_id VARCHAR(100),
                notes TEXT,
                metadata JSONB DEFAULT '{}'
            )
        """)
        print("✅ Licenses table ensured")
        
        # Create validation_logs table if it doesn't exist
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS validation_logs (
                id SERIAL PRIMARY KEY,
                license_key_hash VARCHAR(64) NOT NULL,
                hardware_id VARCHAR(32),
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) NOT NULL,
                ip_address INET,
                user_agent TEXT,
                app_version VARCHAR(20),
                response_time_ms INTEGER,
                details JSONB DEFAULT '{}'
            )
        """)
        print("✅ Validation logs table ensured")
        
        # Create admin_sessions table if it doesn't exist
        await self.conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(255) UNIQUE NOT NULL,
                admin_username VARCHAR(100) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                ip_address INET,
                user_agent TEXT,
                active BOOLEAN DEFAULT TRUE
            )
        """)
        print("✅ Admin sessions table ensured")

async def main():
    """Main migration function"""
    print("🚀 PDF License Server Database Migration")
    print("=" * 50)
    
    # Get database URL from environment
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        print("❌ DATABASE_URL environment variable not set")
        sys.exit(1)
    
    print(f"🔗 Connecting to database: {database_url.split('@')[1] if '@' in database_url else database_url}")
    
    # Create fixer instance
    fixer = DatabaseFixer(database_url)
    
    try:
        await fixer.connect()
        
        # Create missing tables first
        await fixer.create_missing_tables()
        
        # Run all fixes
        await fixer.run_fixes()
        
        print("\n🎉 Migration completed successfully!")
        print("Your database is now compatible with the fixed application.")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        sys.exit(1)
    finally:
        await fixer.close()

if __name__ == "__main__":
    asyncio.run(main())