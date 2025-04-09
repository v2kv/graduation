#!/bin/bash

# Exit on any error
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting SOUQKHANA deployment...${NC}"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run this script with sudo or as root${NC}"
  exit 1
fi

# Update system packages
echo -e "${GREEN}Updating system packages...${NC}"
apt update && apt upgrade -y

# Install required dependencies
echo -e "${GREEN}Installing required dependencies...${NC}"
apt install -y python3 python3-pip python3-venv mysql-server libmysqlclient-dev build-essential libssl-dev libffi-dev python3-dev

# Create souqkhana user
echo -e "${GREEN}Creating souqkhana user...${NC}"
id -u souqkhana &>/dev/null || useradd -m -s /bin/bash souqkhana

# Create necessary directories
echo -e "${GREEN}Creating necessary directories...${NC}"
mkdir -p /var/www/souqkhana
mkdir -p /var/log/gunicorn
mkdir -p /var/log/caddy

# Ensure proper permissions
chown -R souqkhana:www-data /var/www/souqkhana
chmod -R 775 /var/www/souqkhana
chown -R souqkhana:www-data /var/log/gunicorn
chmod -R 775 /var/log/gunicorn
mkdir -p /var/www/souqkhana/logs
chown -R souqkhana:www-data /var/www/souqkhana/logs
chmod -R 775 /var/www/souqkhana/logs

# Configure MySQL
echo -e "${GREEN}Configuring MySQL...${NC}"
systemctl enable mysql
systemctl start mysql

# Prompt for MySQL root password
echo -e "${GREEN}Please enter a password for MySQL root user:${NC}"
read -s MYSQL_ROOT_PASSWORD
echo

# Set MySQL root password
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASSWORD';"
mysql -e "FLUSH PRIVILEGES;"

# Create database and user
echo -e "${GREEN}Creating database and user for SOUQKHANA...${NC}"
echo -e "${GREEN}Please enter a password for the souqkhana database user:${NC}"
read -s SOUQKHANA_DB_PASSWORD
echo

mysql -u root -p$MYSQL_ROOT_PASSWORD -e "CREATE DATABASE IF NOT EXISTS souqkhana CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p$MYSQL_ROOT_PASSWORD -e "CREATE USER IF NOT EXISTS 'souqkhana'@'localhost' IDENTIFIED BY '$SOUQKHANA_DB_PASSWORD';"
mysql -u root -p$MYSQL_ROOT_PASSWORD -e "GRANT ALL PRIVILEGES ON souqkhana.* TO 'souqkhana'@'localhost';"
mysql -u root -p$MYSQL_ROOT_PASSWORD -e "FLUSH PRIVILEGES;"

# Install Caddy
echo -e "${GREEN}Installing Caddy...${NC}"
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install -y caddy

# Set up Caddy with the Cloudflare DNS module
echo -e "${GREEN}Setting up Caddy with Cloudflare DNS module...${NC}"
caddy add-package github.com/caddy-dns/cloudflare

# Copy Caddyfile to the correct location
echo -e "${GREEN}Configuring Caddy...${NC}"
cp /var/www/souqkhana/Caddyfile /etc/caddy/Caddyfile
systemctl enable caddy
systemctl restart caddy

# Generate self-signed certificates for development
echo -e "${GREEN}Generating self-signed certificates for development...${NC}"
openssl req -x509 -nodes -newkey rsa:4096 -days 365 -keyout /var/www/souqkhana/key.pem -out /var/www/souqkhana/cert.pem -subj "/CN=souqkhana.com"
chown souqkhana:www-data /var/www/souqkhana/*.pem
chmod 640 /var/www/souqkhana/*.pem

# Set up Python virtual environment and install dependencies
echo -e "${GREEN}Setting up Python virtual environment and installing dependencies...${NC}"
su - souqkhana -c "cd /var/www/souqkhana && python3 -m venv venv"
su - souqkhana -c "cd /var/www/souqkhana && source venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt && pip install gunicorn"

# Set up the systemd service for Gunicorn
echo -e "${GREEN}Setting up the systemd service for Gunicorn...${NC}"
cp /var/www/souqkhana/gunicorn.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable gunicorn.service
systemctl start gunicorn.service

# Prompt to create .env file
echo -e "${GREEN}Creating .env file...${NC}"
echo "Please fill in the following information for your .env file:"

echo -n "Enter a secure random SECRET_KEY: "
read SECRET_KEY

echo -n "Enter your ADMIN_REGISTRATION_TOKEN: "
read ADMIN_REGISTRATION_TOKEN

echo -n "Enter your STRIPE_PUBLIC_KEY: "
read STRIPE_PUBLIC_KEY

echo -n "Enter your STRIPE_SECRET_KEY: "
read STRIPE_SECRET_KEY

echo -n "Enter your OPENROUTER_API_KEY: "
read OPENROUTER_API_KEY

echo -n "Enter your MAIL_USERNAME (email): "
read MAIL_USERNAME

echo -n "Enter your MAIL_PASSWORD (app password): "
read -s MAIL_PASSWORD
echo

echo -n "Enter your Cloudflare API Token (for DNS verification): "
read CF_API_TOKEN

# Create the .env file
cat > /var/www/souqkhana/.env << EOF
SECRET_KEY=$SECRET_KEY
DATABASE_URL=mysql+pymysql://souqkhana:$SOUQKHANA_DB_PASSWORD@localhost/souqkhana
ADMIN_REGISTRATION_TOKEN=$ADMIN_REGISTRATION_TOKEN
STRIPE_PUBLIC_KEY=$STRIPE_PUBLIC_KEY
STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY
OPENROUTER_API_KEY=$OPENROUTER_API_KEY
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=$MAIL_USERNAME
MAIL_PASSWORD=$MAIL_PASSWORD
MAIL_SENDER_NAME=SOUQKHANA
MAIL_SENDER_EMAIL=no-reply@souqkhana.com
CF_API_TOKEN=$CF_API_TOKEN
EOF

# Set proper ownership and permissions for .env file
chown souqkhana:www-data /var/www/souqkhana/.env
chmod 640 /var/www/souqkhana/.env

# Initialize the database
echo -e "${GREEN}Initializing the database...${NC}"
su - souqkhana -c "cd /var/www/souqkhana && source venv/bin/activate && flask db create"

# Restart services to apply all changes
echo -e "${GREEN}Restarting services...${NC}"
systemctl restart gunicorn
systemctl restart caddy

echo -e "${GREEN}Deployment completed successfully!${NC}"
echo -e "${GREEN}Your SOUQKHANA e-commerce platform is now running at https://souqkhana.com${NC}"

# Display admin registration link
echo -e "${GREEN}You can register as admin using the following URL:${NC}"
echo -e "${GREEN}https://souqkhana.com/admin/register/$ADMIN_REGISTRATION_TOKEN${NC}"

# Display application logs
echo -e "${GREEN}To view application logs, use:${NC}"
echo -e "${GREEN}  - Gunicorn access logs: tail -f /var/log/gunicorn/access.log${NC}"
echo -e "${GREEN}  - Gunicorn error logs: tail -f /var/log/gunicorn/error.log${NC}"
echo -e "${GREEN}  - Application logs: tail -f /var/www/souqkhana/logs/souqkhana.log${NC}"
echo -e "${GREEN}  - Caddy logs: tail -f /var/log/caddy/souqkhana.log${NC}"