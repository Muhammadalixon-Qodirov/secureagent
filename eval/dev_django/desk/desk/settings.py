SECRET_KEY = "dev-only"
INSTALLED_APPS = ["django.contrib.auth", "rest_framework", "tickets"]
AUTH_USER_MODEL = "tickets.Agent"
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}
