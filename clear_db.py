from app import app, db, User

def clear_database():
    with app.app_context():
        # Delete all users
        User.query.delete()
        # Commit the changes
        db.session.commit()
        print("All database data has been cleared!")

if __name__ == "__main__":
    clear_database() 