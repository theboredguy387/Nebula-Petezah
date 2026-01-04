import { EmbedBuilder } from 'discord.js';
import dotenv from 'dotenv';
import os from 'node:os';

dotenv.config({ path: '.env.production' });

const OWNER_ID = '1311722282317779097';
const ALERT_COOLDOWN = 600000;
const ATTACK_END_TIMEOUT = 180000;
const WINDOW_SIZE = 10000;
const CPU_THRESHOLD = 75;

class DDoSShield {
  constructor(client) {
    this.client = client;
    this.logChannelId = null;
    this.isUnderAttack = false;
    this.attackStartTime = null;
    this.mitigatedCount = 0;
    this.lastAlertTime = 0;
    this.lastBlockTime = 0;
    this.attackEndTimer = null;
    this.startupGracePeriod = true;
    setTimeout(() => { this.startupGracePeriod = false; }, 600000);

    this.ipBlocks = new Map();
    this.blockTypes = new Map();
    this.challengeHits = new Map();
    this.ipRequests = new Map();

    this.cleanupInterval = setInterval(() => this.cleanupOldEntries(), 30000);
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

  getCpuUsage() {
    const cpus = os.cpus();
    let idleMs = 0;
    let totalMs = 0;
    cpus.forEach(cpu => {
      for (const type in cpu.times) {
        totalMs += cpu.times[type];
      }
      idleMs += cpu.times.idle;
    });
    const idle = idleMs / cpus.length;
    const total = totalMs / cpus.length;
    return 100 - (100 * idle / total);
  }

  incrementBlocked(ip, type = 'unknown') {
    this.mitigatedCount++;
    this.lastBlockTime = Date.now();

    const now = Date.now();
    const ipData = this.ipBlocks.get(ip) || { blocks: [], types: {} };
    ipData.blocks.push(now);
    ipData.types[type] = (ipData.types[type] || 0) + 1;

    ipData.blocks = ipData.blocks.filter(t => now - t < 60000);
    this.ipBlocks.set(ip, ipData);

    this.blockTypes.set(type, (this.blockTypes.get(type) || 0) + 1);

    this.checkAttackConditions(ip);

    if (this.isUnderAttack && this.attackEndTimer) {
      clearTimeout(this.attackEndTimer);
      this.attackEndTimer = setTimeout(() => this.endAttackAlert(), ATTACK_END_TIMEOUT);
    }
  }

  trackChallengeHit(ip) {
    const now = Date.now();
    const hits = this.challengeHits.get(ip) || [];
    hits.push(now);
    this.challengeHits.set(ip, hits.filter(t => now - t < 30000));
  }

  getRecentBlocks(ip, windowMs = WINDOW_SIZE) {
    const ipData = this.ipBlocks.get(ip);
    if (!ipData) return 0;
    const now = Date.now();
    return ipData.blocks.filter(t => now - t < windowMs).length;
  }

  getTotalBlocks(ip) {
    const ipData = this.ipBlocks.get(ip);
    return ipData ? ipData.blocks.length : 0;
  }

  getTopAbusers(limit = 5) {
    const abusers = [];
    for (const [ip, data] of this.ipBlocks.entries()) {
      const count = data.blocks.length;
      if (count > 0) {
        const topType = Object.entries(data.types).sort((a, b) => b[1] - a[1])[0];
        abusers.push({ ip, count, primaryType: topType ? topType[0] : 'unknown' });
      }
    }
    return abusers.sort((a, b) => b.count - a.count).slice(0, limit);
  }

  getChallengeSpike() {
    const now = Date.now();
    let totalHits = 0;
    let uniqueIps = 0;
    
    for (const [ip, hits] of this.challengeHits.entries()) {
      const recent = hits.filter(t => now - t < 30000);
      if (recent.length > 0) {
        totalHits += recent.length;
        uniqueIps++;
      }
    }
    
    return { totalHits, uniqueIps };
  }

  checkAttackConditions(ip, systemState = null) {
    if (this.isUnderAttack || this.startupGracePeriod) return;
    
    const now = Date.now();
    if (now - this.lastAlertTime < ALERT_COOLDOWN) return;

    const recentBlocks = this.getRecentBlocks(ip, WINDOW_SIZE);
    const totalBlocks = this.getTotalBlocks(ip);
    const cpuUsage = this.getCpuUsage();
    const { uniqueIps } = this.getChallengeSpike();

    const shouldAlert = (
      recentBlocks > 50 ||
      totalBlocks > 200 ||
      (cpuUsage > CPU_THRESHOLD && totalBlocks > 100) ||
      uniqueIps > 100 ||
      (systemState?.cpuHigh && totalBlocks > 50) ||
      (systemState?.totalWS > 25000 && totalBlocks > 30)
    );

    if (shouldAlert) {
      this.lastAlertTime = now;
      this.startAttackAlert(systemState);
    }
  }

  async startAttackAlert(systemState = null) {
    if (this.isUnderAttack) return;

    this.isUnderAttack = true;
    this.attackStartTime = Date.now();
    const initialCount = this.mitigatedCount;

    const topAbusers = this.getTopAbusers(5);
    const cpuUsage = this.getCpuUsage().toFixed(1);
    
    const blockTypesSummary = Array.from(this.blockTypes.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([type, count]) => `${type}: ${count}`)
      .join('\n') || 'N/A';

    const systemStatus = systemState 
      ? `CPU: ${cpuUsage}%\nConnections: ${systemState.activeConnections}\nWS: ${systemState.totalWS}\nTotal Blocks: ${this.mitigatedCount}`
      : `CPU: ${cpuUsage}%\nTotal Blocks: ${this.mitigatedCount}`;

    const embed = new EmbedBuilder()
      .setTitle('🛡️ DDoS Attack Detected!')
      .setDescription('High volume of malicious traffic identified.\nStarting automated mitigation...')
      .addFields(
        { name: 'Top Abusers', value: topAbusers.map(a => `${a.ip} — ${a.count} blocks (${a.primaryType})`).join('\n') || 'N/A', inline: false },
        { name: 'Block Reasons', value: blockTypesSummary, inline: true },
        { name: 'System Status', value: systemStatus, inline: true }
      )
      .setColor('#ff0000')
      .setTimestamp();

    await this.sendLog(null, embed);

    this.attackEndTimer = setTimeout(() => this.endAttackAlert(), ATTACK_END_TIMEOUT);
  }

  async endAttackAlert() {
    if (!this.isUnderAttack) return;

    this.isUnderAttack = false;
    if (this.attackEndTimer) {
      clearTimeout(this.attackEndTimer);
      this.attackEndTimer = null;
    }

    const duration = Math.floor((Date.now() - this.attackStartTime) / 1000);
    const topAbusers = this.getTopAbusers(5);
    
    const embed = new EmbedBuilder()
      .setTitle('✅ Attack Mitigated Successfully')
      .setDescription(`DDoS attack neutralized after ${duration} seconds.\nTotal requests blocked: **${this.mitigatedCount.toLocaleString()}**`)
      .addFields(
        { name: 'Top Attackers', value: topAbusers.map(a => `${a.ip} — ${a.count} blocks`).join('\n') || 'N/A' }
      )
      .setColor('#00ff00')
      .setTimestamp();

    await this.sendLog(null, embed);
  }

  cleanupOldEntries() {
    const now = Date.now();
    
    for (const [ip, data] of this.ipBlocks.entries()) {
      data.blocks = data.blocks.filter(t => now - t < 60000);
      if (data.blocks.length === 0) {
        this.ipBlocks.delete(ip);
      }
    }

    for (const [ip, hits] of this.challengeHits.entries()) {
      const recent = hits.filter(t => now - t < 30000);
      if (recent.length === 0) {
        this.challengeHits.delete(ip);
      } else {
        this.challengeHits.set(ip, recent);
      }
    }

    for (const [ip, data] of this.ipRequests.entries()) {
      if (now - data.lastSeen > 60000) {
        this.ipRequests.delete(ip);
      }
    }
  }

  trackRequest(ip) {
    const now = Date.now();
    const data = this.ipRequests.get(ip) || { count: 0, lastSeen: now, blocks: 0 };
    data.count++;
    data.lastSeen = now;
    this.ipRequests.set(ip, data);

    const timeWindow = now - (data.firstSeen || now);
    const rate = timeWindow > 0 ? (data.count / (timeWindow / 1000)) : 0;

    if (data.count > 50000 || rate > 10000) {
      this.incrementBlocked(ip, 'request_flood');
    }
  }

  trackWS(ip, delta) {
    const current = this.ipRequests.get(ip)?.ws || 0;
    const updated = Math.max(0, current + delta);
    
    const data = this.ipRequests.get(ip) || { count: 0, lastSeen: Date.now(), ws: 0 };
    data.ws = updated;
    this.ipRequests.set(ip, data);

    if (delta < 0) return;

    const cpuUsage = this.getCpuUsage();
    if (updated > 500 && cpuUsage > CPU_THRESHOLD) {
      this.incrementBlocked(ip, 'ws_flood');
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

        for (let i = 0; i < 100; i++) {
          this.incrementBlocked(`192.168.1.${i % 10}`, i % 3 === 0 ? 'pow_fail' : i % 3 === 1 ? 'rate_limit' : 'ws_cap');
          if (i % 10 === 0) await new Promise(r => setTimeout(r, 100));
        }

        setTimeout(() => this.endAttackAlert(), 15000);
      }
    });
  }
}

export const ddosShield = (client) => {
  return new DDoSShield(client);
};
