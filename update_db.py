from app import create_app, db  # If you have a create_app function

if __name__ == '__main__':
    app = create_app()  # Create the app instance
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("✅ Database tables created/updated successfully!")
        
        # Verify the table was created
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        if 'shared_passwords' in tables:
            print("✅ shared_passwords table confirmed!")
            
            # Show columns to double-check
            columns = inspector.get_columns('shared_passwords')
            print("Columns:", [col['name'] for col in columns])
        else:
            print("❌ shared_passwords table not found")