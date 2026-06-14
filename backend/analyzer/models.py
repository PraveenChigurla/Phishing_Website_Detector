from django.db import models

class ScanHistory(models.Model):
    VERDICT_CHOICES = [
        ('SAFE', 'Safe'),
        ('SUSPICIOUS', 'Suspicious'),
        ('PHISHING', 'Phishing'),
    ]

    url = models.URLField(max_length=2048)
    scanned_at = models.DateTimeField(auto_now_add=True)
    final_score = models.FloatField()
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES)
    # JSONField stores the detail weights and external scan outcomes
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-scanned_at']
        verbose_name_plural = "Scan Histories"

    def __str__(self):
        return f"{self.url} - {self.verdict} ({self.final_score})"


class DomainPolicy(models.Model):
    POLICY_CHOICES = [
        ('whitelist', 'Whitelist'),
        ('blacklist', 'Blacklist'),
    ]

    domain = models.CharField(max_length=253, unique=True)
    policy = models.CharField(max_length=20, choices=POLICY_CHOICES)
    reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name_plural = "Domain Policies"

    def __str__(self):
        return f"{self.domain} - {self.policy.upper()}"
