import os
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishing_backend.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()
username = 'admin'
email = 'admin@example.com'
password = 'adminpassword'

def check_and_create_admin():
    if not User.objects.filter(username=username).exists():
        print(f"Creating superuser '{username}'...")
        User.objects.create_superuser(username=username, email=email, password=password)
        print("Superuser created successfully!")
        print("---------------------------------------")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print("---------------------------------------")
    else:
        print(f"Superuser '{username}' already exists. No action needed.")

if __name__ == '__main__':
    check_and_create_admin()
