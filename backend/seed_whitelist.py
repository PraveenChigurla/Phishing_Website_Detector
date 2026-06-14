import os
import django

# Set up Django settings environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishing_backend.settings')
django.setup()

from analyzer.models import DomainPolicy

# Top 30 global trusted domains to seed into the database
GLOBAL_WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
    "netflix.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "zoom.us", "live.com", "office.com", "bing.com", "pinterest.com",
    "fandom.com", "ebay.com", "imgur.com", "medium.com", "imdb.com",
    "dropbox.com", "salesforce.com", "craigslist.org", "adobe.com", "spotify.com"
]

def seed():
    print("Seeding global whitelist into Django database...")
    created_count = 0
    for domain in GLOBAL_WHITELIST:
        obj, created = DomainPolicy.objects.get_or_create(
            domain=domain,
            defaults={
                'policy': 'whitelist',
                'reason': 'Global popular trusted domain (seeded)'
            }
        )
        if created:
            created_count += 1
            print(f"Added: {domain}")
        else:
            # Ensure it is whitelisted if it already existed with a different policy
            if obj.policy != 'whitelist':
                obj.policy = 'whitelist'
                obj.reason = 'Global popular trusted domain (seeded override)'
                obj.save()
                print(f"Updated policy to whitelist for: {domain}")
                
    print(f"Seeding completed successfully. Added {created_count} new domains to DomainPolicy.")

if __name__ == '__main__':
    seed()
