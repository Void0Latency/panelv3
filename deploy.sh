#!/bin/bash
# ============================================
# VOIDLATENCY PANEL DEPLOYER - SHELL SCRIPT
# ============================================

echo "╔═══════════════════════════════════════════╗"
echo "║        VOIDLATENCY PANEL DEPLOYER       ║"
echo "╚═══════════════════════════════════════════╝"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Create D1 Database
echo "📊 Creating D1 Database..."
npx wrangler d1 create voidlatency-db

echo ""
echo "📝 Copy the database_id from above and paste it here:"
read -p "database_id: " DB_ID

# Update wrangler.toml
sed -i "s/database_id = \".*\"/database_id = \"$DB_ID\"/" wrangler.toml

# Run migrations
echo "🗄️ Running database migrations..."
npx wrangler d1 execute voidlatency-db --file=./schema.sql

# Deploy
echo "🚀 Deploying to Cloudflare Workers..."
npx wrangler deploy

echo ""
echo "✅ Deployment complete!"
echo "🌐 Visit: https://YOUR-WORKER.workers.dev/panel"
echo "📝 Set your admin password"
echo "🔑 Username: admin"
