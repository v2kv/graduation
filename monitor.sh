#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run this script with sudo or as root${NC}"
  exit 1
fi

# Log file
LOG_FILE="/var/log/souqkhana_monitor.log"
EMAIL="contact@souqkhana.com"  

echo "===========================================" >> $LOG_FILE
echo "SOUQKHANA Monitoring - $(date)" >> $LOG_FILE
echo "===========================================" >> $LOG_FILE

# Check if services are running
echo -e "${GREEN}Checking services...${NC}"
echo "Checking services:" >> $LOG_FILE

check_service() {
  service=$1
  status=$(systemctl is-active $service)
  if [ "$status" = "active" ]; then
    echo -e "  ${GREEN}✓ $service is running${NC}"
    echo "  ✓ $service is running" >> $LOG_FILE
  else
    echo -e "  ${RED}✗ $service is not running${NC}"
    echo "  ✗ $service is not running" >> $LOG_FILE
    # Try to restart the service
    echo -e "${YELLOW}Attempting to restart $service...${NC}"
    systemctl restart $service
    echo "Attempting to restart $service..." >> $LOG_FILE
    # Send alert email
    echo "ALERT: $service on SOUQKHANA server is down and has been restarted." | mail -s "SOUQKHANA Service Down: $service" $EMAIL
  fi
}

# Check important services
check_service gunicorn
check_service caddy
check_service mysql

# Check disk space
echo -e "\n${GREEN}Checking disk space...${NC}"
echo -e "\nChecking disk space:" >> $LOG_FILE
df_output=$(df -h / | tail -n 1)
disk_usage=$(echo $df_output | awk '{print $5}' | tr -d '%')

echo "  Disk usage: $disk_usage%" >> $LOG_FILE
echo -e "  Disk usage: ${YELLOW}$disk_usage%${NC}"

if [ $disk_usage -gt 90 ]; then
  echo -e "  ${RED}WARNING: Disk space is critically low!${NC}"
  echo "  WARNING: Disk space is critically low!" >> $LOG_FILE
  echo "ALERT: Disk space on SOUQKHANA server is critically low ($disk_usage%)." | mail -s "SOUQKHANA Disk Space Alert" $EMAIL
elif [ $disk_usage -gt 80 ]; then
  echo -e "  ${YELLOW}WARNING: Disk space is getting low.${NC}"
  echo "  WARNING: Disk space is getting low." >> $LOG_FILE
fi

# Check memory usage
echo -e "\n${GREEN}Checking memory usage...${NC}"
echo -e "\nChecking memory usage:" >> $LOG_FILE
mem_total=$(free -m | grep Mem | awk '{print $2}')
mem_used=$(free -m | grep Mem | awk '{print $3}')
mem_usage=$((mem_used * 100 / mem_total))

echo "  Memory usage: $mem_usage% ($mem_used MB / $mem_total MB)" >> $LOG_FILE
echo -e "  Memory usage: ${YELLOW}$mem_usage% ($mem_used MB / $mem_total MB)${NC}"

if [ $mem_usage -gt 90 ]; then
  echo -e "  ${RED}WARNING: Memory usage is critically high!${NC}"
  echo "  WARNING: Memory usage is critically high!" >> $LOG_FILE
  echo "ALERT: Memory usage on SOUQKHANA server is critically high ($mem_usage%)." | mail -s "SOUQKHANA Memory Usage Alert" $EMAIL
fi

# Check for failed login attempts
echo -e "\n${GREEN}Checking for failed login attempts...${NC}"
echo -e "\nChecking for failed login attempts:" >> $LOG_FILE
recent_fails=$(grep "Failed password" /var/log/auth.log | wc -l)

echo "  Recent failed login attempts: $recent_fails" >> $LOG_FILE
echo -e "  Recent failed login attempts: ${YELLOW}$recent_fails${NC}"

if [ $recent_fails -gt 10 ]; then
  echo -e "  ${RED}WARNING: High number of failed login attempts detected!${NC}"
  echo "  WARNING: High number of failed login attempts detected!" >> $LOG_FILE
  echo "ALERT: High number of failed login attempts ($recent_fails) detected on SOUQKHANA server." | mail -s "SOUQKHANA Security Alert" $EMAIL
fi

# Check database connection
echo -e "\n${GREEN}Checking database connection...${NC}"
echo -e "\nChecking database connection:" >> $LOG_FILE

# Source environment variables from the application for database connection
if [ -f /var/www/souqkhana/.env ]; then
  source <(grep -v '^#' /var/www/souqkhana/.env | sed -E 's/(.*)=(.*)/export \1="\2"/')
  
  # Extract database credentials from DATABASE_URL
  if [[ $DATABASE_URL =~ mysql\+pymysql://([^:]+):([^@]+)@([^/]+)/(.+) ]]; then
    DB_USER="${BASH_REMATCH[1]}"
    DB_PASS="${BASH_REMATCH[2]}"
    DB_HOST="${BASH_REMATCH[3]}"
    DB_NAME="${BASH_REMATCH[4]}"
    
    # Test database connection
    if mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "SELECT 1" &>/dev/null; then
      echo -e "  ${GREEN}✓ Database connection successful${NC}"
      echo "  ✓ Database connection successful" >> $LOG_FILE
    else
      echo -e "  ${RED}✗ Database connection failed${NC}"
      echo "  ✗ Database connection failed" >> $LOG_FILE
      echo "ALERT: Database connection failed on SOUQKHANA server." | mail -s "SOUQKHANA Database Alert" $EMAIL
    fi
  else
    echo -e "  ${RED}✗ Could not parse DATABASE_URL from .env file${NC}"
    echo "  ✗ Could not parse DATABASE_URL from .env file" >> $LOG_FILE
  fi
else
  echo -e "  ${RED}✗ .env file not found${NC}"
  echo "  ✗ .env file not found" >> $LOG_FILE
fi

# Check website accessibility
echo -e "\n${GREEN}Checking website accessibility...${NC}"
echo -e "\nChecking website accessibility:" >> $LOG_FILE

http_status=$(curl -s -o /dev/null -w "%{http_code}" https://souqkhana.com)

if [ "$http_status" = "200" ]; then
  echo -e "  ${GREEN}✓ Website is accessible (HTTP 200)${NC}"
  echo "  ✓ Website is accessible (HTTP 200)" >> $LOG_FILE
else
  echo -e "  ${RED}✗ Website is not accessible (HTTP $http_status)${NC}"
  echo "  ✗ Website is not accessible (HTTP $http_status)" >> $LOG_FILE
  echo "ALERT: SOUQKHANA website is not accessible (HTTP $http_status)." | mail -s "SOUQKHANA Website Accessibility Alert" $EMAIL
fi

# Check recent application errors
echo -e "\n${GREEN}Checking for recent application errors...${NC}"
echo -e "\nChecking for recent application errors:" >> $LOG_FILE

recent_errors=$(grep -i "error\|exception" /var/www/souqkhana/logs/souqkhana.log | tail -n 10)

if [ -n "$recent_errors" ]; then
  error_count=$(echo "$recent_errors" | wc -l)
  echo -e "  ${YELLOW}Found $error_count recent errors. Latest errors:${NC}"
  echo "  Found $error_count recent errors. Latest errors:" >> $LOG_FILE
  echo "$recent_errors" | tail -n 3 >> $LOG_FILE
  echo -e "${YELLOW}$(echo "$recent_errors" | tail -n 3)${NC}"
  
  if [ $error_count -gt 5 ]; then
    echo "ALERT: Multiple application errors ($error_count) detected in SOUQKHANA logs." | mail -s "SOUQKHANA Application Error Alert" $EMAIL
  fi
else
  echo -e "  ${GREEN}✓ No recent application errors${NC}"
  echo "  ✓ No recent application errors" >> $LOG_FILE
fi

# Add to crontab if not already there
if ! crontab -l | grep -q "souqkhana_monitor.sh"; then
  echo -e "\n${YELLOW}Would you like to add this monitor to run every hour? (y/n)${NC}"
  read add_cron
  if [[ $add_cron == "y" ]]; then
    crontab_entry="0 * * * * /usr/local/bin/souqkhana_monitor.sh"
    (crontab -l 2>/dev/null; echo "$crontab_entry") | crontab -
    echo -e "${GREEN}Monitor added to crontab to run every hour.${NC}"
  fi
fi

echo -e "\n${GREEN}Monitoring complete. Log saved to $LOG_FILE${NC}"