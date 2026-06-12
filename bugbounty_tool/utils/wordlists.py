"""Internal wordlists used as fallbacks when the user does not provide one."""

# 50 most common subdomains observed in real-world recon engagements.
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "admin", "test", "dev", "staging", "beta", "api", "api-dev",
    "blog", "shop", "store", "vpn", "ssh", "remote", "secure", "portal",
    "intranet", "extranet", "support", "help", "docs", "wiki", "git", "gitlab",
    "jenkins", "ci", "cd", "build", "deploy", "files", "static", "cdn",
    "assets", "media", "img", "images", "video", "monitoring", "status",
    "grafana", "kibana",
]

# 40 common sensitive directories/files used as fallback for fuzzing.
DEFAULT_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "backup", "backups", "old", "test", "dev", "staging", ".git", ".gitignore",
    ".env", ".env.local", ".env.production", "config", "config.php",
    "configuration.php", "web.config", ".htaccess", "robots.txt", "sitemap.xml",
    "server-status", "server-info", "info.php", "phpinfo.php", "console",
    "api", "api/v1", "swagger", "swagger-ui.html", "graphql", "actuator",
    "actuator/health", ".DS_Store", "debug", "trace", "uploads",
]
