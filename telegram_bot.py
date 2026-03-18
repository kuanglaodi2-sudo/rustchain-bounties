#!/usr/bin/env python3
"""
RustChain Telegram Bot
A bot that queries the RustChain API for wallet balance, miner stats, price, and health.

Bounty: https://github.com/Scottcjn/rustchain-bounties/issues/1597
Reward: 10 RTC
"""

import os
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Configuration
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
RUSTCHAIN_API_URL = os.environ.get("RUSTCHAIN_API_URL", "https://rustchain.org/api")


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    await update.message.reply_text(
        "🦀 *RustChain Telegram Bot*\n\n"
        "Commands:\n"
        "/balance <wallet> - Get RTC balance\n"
        "/miners - Get miner stats\n"
        "/price - Get RTC price\n"
        "/health - Get network health\n"
        "/help - Show this help message",
        parse_mode="Markdown"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    await start_command(update, context)


async def balance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /balance command"""
    if not context.args:
        await update.message.reply_text("Usage: /balance <wallet_address>")
        return
    
    wallet = context.args[0]
    
    try:
        # Query RustChain API for balance
        response = requests.get(f"{RUSTCHAIN_API_URL}/wallet/{wallet}", timeout=10)
        data = response.json()
        
        if data.get("ok"):
            balance = data.get("balance", 0)
            await update.message.reply_text(
                f"✅ *Wallet Balance*\n\n"
                f"`{wallet[:8]}...{wallet[-8:]}`\n"
                f"Balance: *{balance} RTC*",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to fetch balance: {str(e)}")


async def miners_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /miners command"""
    try:
        response = requests.get(f"{RUSTCHAIN_API_URL}/network/miners", timeout=10)
        data = response.json()
        
        if data.get("ok"):
            miners = data.get("miner_count", 0)
            await update.message.reply_text(
                f"⛏️ *Miner Stats*\n\n"
                f"Active Miners: *{miners}*",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to fetch miners: {str(e)}")


async def price_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /price command"""
    try:
        response = requests.get(f"{RUSTCHAIN_API_URL}/market/price", timeout=10)
        data = response.json()
        
        if data.get("ok"):
            price = data.get("price_usd", 0)
            await update.message.reply_text(
                f"💰 *RTC Price*\n\n"
                f"Price: *${price}*",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to fetch price: {str(e)}")


async def health_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /health command"""
    try:
        response = requests.get(f"{RUSTCHAIN_API_URL}/network/health", timeout=10)
        data = response.json()
        
        if data.get("ok"):
            status = data.get("status", "unknown")
            epoch = data.get("current_epoch", 0)
            await update.message.reply_text(
                f"❤️ *Network Health*\n\n"
                f"Status: *{status}*\n"
                f"Current Epoch: *{epoch}*",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(f"❌ Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to fetch health: {str(e)}")


async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle unknown messages"""
    await update.message.reply_text(
        "Unknown command. Use /help to see available commands."
    )


def main():
    """Main function to run the bot"""
    if not TELEGRAM_BOT_TOKEN:
        print("Error: TELEGRAM_BOT_TOKEN environment variable not set")
        return
    
    # Create the Application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("balance", balance_command))
    application.add_handler(CommandHandler("miners", miners_command))
    application.add_handler(CommandHandler("price", price_command))
    application.add_handler(CommandHandler("health", health_command))
    
    # Add echo handler for unknown commands
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))
    
    # Start the bot
    print("🤖 RustChain Telegram Bot starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
