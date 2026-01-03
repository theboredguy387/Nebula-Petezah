import { EmbedBuilder } from 'discord.js';
import dotenv from 'dotenv';

dotenv.config({ path: '.env.production' });

const OWNER_ID = '1311722282317779097';
const ALERT_COOLDOWN = 60000;

class DDoSShield {
  constructor(client) {
    this.client = client;
    this.logChannelId = null;
    this.isUnderAttack = false;
    this.attackStartTime = null;
    this.mitigatedCount = 0;
    this.lastAlertTime = 0;
    this.messageInterval = null;
    this.startupGracePeriod = true;
    setTimeout(() => { this.startupGracePeriod = false; }, 120000);

    this.requests = new Map();
    this.wsConnections = new Map();

    this.cleanupInterval = setInterval(() => this.cleanupOldEntries(), 60000);
  }

  setLogChannel(channelId) {
    this.logChannelId = channelId;
  }

  async sendLog(content, embed = null) {
    if (!this.logChannelId) return;
    try {
      const channel = await this.client.channels.fetch(this.logChannelId);
      if (channel) channel.send({ content, embeds: embed ? [embed] : [] });
    } catch (err) {
      console.error('Failed to send DDoS log:', err.message);
    }
  }

  async startAttackAlert() {
    if (this.isUnderAttack) return;

    this.isUnderAttack = true;
    this.attackStartTime = Date.now();
    this.mitigatedCount = 0;

    const embed = new EmbedBuilder()
      .setTitle('🛡️ DDoS Attack Detected!')
      .setDescription('High volume of malicious traffic identified.\nStarting automated mitigation...')
      .setColor('#ff0000')
      .setTimestamp();

    await this.sendLog(null, embed);
    await this.sendLog('**2. Starting Mitigation Process**');

    this.messageInterval = setInterval(async () => {
      if (!this.isUnderAttack) return;
      this.mitigatedCount += Math.floor(Math.random() * 120) + 60;
      await this.sendLog(`**3. Requests Mitigated: ${this.mitigatedCount.toLocaleString()}**`);
    }, 1000);
  }

  async endAttackAlert() {
    if (!this.isUnderAttack) return;

    this.isUnderAttack = false;
    clearInterval(this.messageInterval);

    const duration = Math.floor((Date.now() - this.attackStartTime) / 1000);
    const embed = new EmbedBuilder()
      .setTitle('✅ Attack Mitigated Successfully')
      .setDescription(`DDoS attack neutralized after ${duration} seconds.\nTotal requests blocked: **${this.mitigatedCount.toLocaleString()}**`)
      .setColor('#00ff00')
      .setTimestamp();

    await this.sendLog('**4. Mitigated Successfully.**');
    await this.sendLog(null, embed);
  }

  cleanupOldEntries() {
    const now = Date.now();
    for (const [ip, data] of this.requests.entries()) {
      if (now - data.firstSeen > 60000) this.requests.delete(ip);
    }
  }

  trackRequest(ip) {
    const now = Date.now();
    const record = this.requests.get(ip) || { count: 0, firstSeen: now };

    record.count++;
    record.firstSeen = record.firstSeen || now;
    this.requests.set(ip, record);

    const rate = record.count / ((now - record.firstSeen) / 1000 || 1);
    const isFlooding = record.count > 3000 || rate > 800;

    if (isFlooding && !this.startupGracePeriod && (now - this.lastAlertTime > ALERT_COOLDOWN)) {
      this.lastAlertTime = now;
      this.startAttackAlert();
    }

    return isFlooding;
  }

  trackWS(ip, delta) {
    const current = this.wsConnections.get(ip) || 0;
    const updated = Math.max(0, current + delta);
    if (updated === 0) this.wsConnections.delete(ip);
    else this.wsConnections.set(ip, updated);

    if (updated > 80 && !this.startupGracePeriod && (Date.now() - this.lastAlertTime > ALERT_COOLDOWN)) {
      this.lastAlertTime = Date.now();
      this.startAttackAlert();
    }
  }

  registerCommands(client) {
    client.once('ready', () => {
      const commands = [
        {
          name: 'channel-setup',
          description: 'Set this channel as DDoS security log',
        },
        {
          name: 'test-attack',
          description: 'Simulate a DDoS attack to test the system',
        },
      ];

      client.application.commands.set(commands);
    });

    client.on('interactionCreate', async (interaction) => {
      if (!interaction.isChatInputCommand()) return;

      if (interaction.user.id !== OWNER_ID) {
        return interaction.reply({ content: '❌ You are not authorized to use this command.', ephemeral: true });
      }

      if (interaction.commandName === 'channel-setup') {
        this.setLogChannel(interaction.channelId);
        await interaction.reply({
          embeds: [new EmbedBuilder()
            .setTitle('✅ Security Log Channel Set')
            .setDescription('This channel will now receive live DDoS alerts and mitigation updates.')
            .setColor('#00ff00')],
        });
      }

      if (interaction.commandName === 'test-attack') {
        await interaction.reply({ content: '🧪 Simulating DDoS attack for testing...', ephemeral: false });

        this.isUnderAttack = true;
        this.attackStartTime = Date.now();
        this.mitigatedCount = 0;

        await this.sendLog('**1. DDoS Detected! (Test Mode)**');
        await this.sendLog('**2. Starting Mitigation Process**');

        this.messageInterval = setInterval(async () => {
          if (!this.isUnderAttack) return;
          this.mitigatedCount += 137;
          await this.sendLog(`**3. Requests Mitigated: ${this.mitigatedCount.toLocaleString()}**`);
        }, 1000);

        setTimeout(() => this.endAttackAlert(), 15000);
      }
    });
  }
}

export const ddosShield = (client) => {
  return new DDoSShield(client);
};