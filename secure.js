import { EmbedBuilder } from 'discord.js';
import dotenv from 'dotenv';
import os from 'node:os';
import process from 'process';

dotenv.config({ path: '.env.production' });

const OWNER_ID = '1311722282317779097';
const ALERT_COOLDOWN = 600000;
const ATTACK_END_TIMEOUT = 300000;
const WINDOW_SIZE = 10000;
const CPU_THRESHOLD = 75;
const MEMORY_THRESHOLD = 1024 * 1024 * 1024 * 2;
const MEMORY_CRITICAL = 1024 * 1024 * 1024 * 1.5;
const PATTERN_DETECTION_WINDOW = 30000;
const ATTACK_PATTERN_THRESHOLD = 50;

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
    this.killSwitchActive = false;
    setTimeout(() => {
      this.startupGracePeriod = false;
    }, 600000);

    this.ipBlocks = new Map();
    this.blockTypes = new Map();
    this.challengeHits = new Map();
    this.ipRequests = new Map();
    this.recentBlocks = [];
    this.attackPatterns = new Map();
    this.memoryStats = { heapUsed: 0, rss: 0, active: false, timestamp: 0 };
    this.wsFlushHistory = [];
    this.autoMitigationActive = false;
    this.attackVector = null;
    this.mitigationActions = [];
    this.trustedFingerprints = new Set();

    this.cleanupInterval = setInterval(() => this.cleanupOldEntries(), 30000);
    this.memoryMonitorInterval = setInterval(() => this.monitorMemory(), 5000);
    this.patternDetectionInterval = setInterval(() => this.detectAttackPatterns(), 10000);
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
    cpus.forEach((cpu) => {
      for (const type in cpu.times) {
        totalMs += cpu.times[type];
      }
      idleMs += cpu.times.idle;
    });
    const idle = idleMs / cpus.length;
    const total = totalMs / cpus.length;
    return 100 - (100 * idle) / total;
  }

  entropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (let char of str) freq[char] = (freq[char] || 0) + 1;
    return -Object.values(freq).reduce((sum, f) => {
      const p = f / str.length;
      return sum + p * Math.log2(p);
    }, 0);
  }

  getRequestVelocity(ip, fingerprint) {
    const ipData = this.ipRequests.get(ip);
    if (!ipData) return 0;
    return ipData.burstCount || 0;
  }

  isKnownGoodBot(ua, ip) {
    const goodBots = [
      /googlebot/i,
      /bingbot/i,
      /slurp/i,
      /duckduckbot/i,
      /baiduspider/i,
      /yandexbot/i
    ];
    return goodBots.some((pattern) => pattern.test(ua));
  }

  calculateRiskScore(ip, fingerprint, reqContext = {}) {
    let score = 0;

    score += this.getRecentBlocks(ip, 10000) * 4;
    score += (this.challengeHits.get(fingerprint)?.length || 0) * 2;

    const blockRate = this.getRecentBlockRate();
    const { totalHits } = this.getChallengeSpike();
    const blockRatio = totalHits > 0 ? blockRate / totalHits : 0;
    score += blockRatio > 0.4 ? 25 : blockRatio > 0.25 ? 12 : 0;

    const req = reqContext.req || {};
    const ua = req.headers?.['user-agent'] || '';
    const uaEntropy = this.entropy(ua);
    score += uaEntropy < 2.5 ? 18 : 0;

    const velocity = this.getRequestVelocity(ip, fingerprint);
    score += velocity > 15 ? 20 : velocity > 8 ? 10 : 0;

    if (this.isKnownGoodBot(ua, ip)) score -= 30;
    if (this.trustedFingerprints?.has(fingerprint)) score -= 45;

    if (this.memoryStats.active) score *= 1.6;

    return Math.min(100, Math.max(0, score));
  }

  incrementBlocked(ip, type = 'unknown') {
    this.mitigatedCount++;
    this.lastBlockTime = Date.now();

    const now = Date.now();
    const ipData = this.ipBlocks.get(ip) || { blocks: [], types: {} };
    ipData.blocks.push(now);
    ipData.types[type] = (ipData.types[type] || 0) + 1;

    ipData.blocks = ipData.blocks.filter((t) => now - t < 60000);
    this.ipBlocks.set(ip, ipData);

    this.blockTypes.set(type, (this.blockTypes.get(type) || 0) + 1);

    this.recentBlocks.push(now);
    this.recentBlocks = this.recentBlocks.filter((t) => now - t < 60000);

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
    this.challengeHits.set(
      ip,
      hits.filter((t) => now - t < 30000)
    );
  }

  getRecentBlocks(ip, windowMs = WINDOW_SIZE) {
    const ipData = this.ipBlocks.get(ip);
    if (!ipData) return 0;
    const now = Date.now();
    return ipData.blocks.filter((t) => now - t < windowMs).length;
  }

  getRecentBlockRate() {
    const now = Date.now();
    const blocksInLastMinute = this.recentBlocks.filter((t) => now - t < 60000).length;
    return blocksInLastMinute;
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
      const recent = hits.filter((t) => now - t < 30000);
      if (recent.length > 0) {
        totalHits += recent.length;
        uniqueIps++;
      }
    }

    return { totalHits, uniqueIps };
  }

  checkAttackConditions(ip, systemState = null) {
    if (this.isUnderAttack || this.startupGracePeriod) return;
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return;

    const now = Date.now();
    if (now - this.lastAlertTime < ALERT_COOLDOWN) return;

    if (!systemState || systemState.state === 'BUSY' || systemState.state === 'NORMAL') return;
    const blockRate = this.getRecentBlockRate();
    const cpuUsage = this.getCpuUsage();
    const { uniqueIps, totalHits } = this.getChallengeSpike();

    const baselineCpu = systemState.baselineCpu || 30;
    const baselineBlockRate = systemState.baselineBlockRate || 5;
    const baselineUniqueIps = systemState.baselineUniqueIps || 50;

    const cpuSpike = cpuUsage > baselineCpu * 1.2;
    const blockRateSpike = blockRate > baselineBlockRate * 3;
    const ipChurn = uniqueIps > baselineUniqueIps * 2;

    const blockRatio = totalHits > 0 ? blockRate / totalHits : 0;
    const powSolveRatio = totalHits > 0 ? (totalHits - blockRate) / totalHits : 1;

    const blockRatioHigh = blockRatio > 0.3;
    const powSolveLow = powSolveRatio < 0.3;

    const isAttack =
      (cpuSpike && blockRatioHigh) ||
      (ipChurn && blockRateSpike && blockRatioHigh) ||
      (blockRateSpike && powSolveLow && blockRatioHigh) ||
      blockRatio > 0.5;

    if (isAttack && systemState.state !== 'ATTACK') {
      this.lastAlertTime = now;
      this.startAttackAlert(systemState);
    }
  }

  async startAttackAlert(systemState = null) {
    if (this.isUnderAttack) return;

    this.isUnderAttack = true;
    this.attackStartTime = Date.now();
    this.mitigationActions = [];

    const topAbusers = this.getTopAbusers(5);
    const cpuUsage = this.getCpuUsage().toFixed(1);
    const mem = process.memoryUsage();
    const memUsage = (mem.heapUsed / 1024 / 1024 / 1024).toFixed(2);

    const blockTypesSummary =
      Array.from(this.blockTypes.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([type, count]) => `${type}: ${count}`)
        .join('\n') || 'N/A';

    const attackPatterns =
      Array.from(this.attackPatterns.entries())
        .slice(0, 3)
        .map(([key, pattern]) => `${pattern.type}: ${pattern.count} from ${pattern.ips.length} IPs`)
        .join('\n') || 'None detected';

    const systemStatus = systemState
      ? `CPU: ${cpuUsage}%\nMemory: ${memUsage}GB\nConnections: ${systemState.activeConnections}\nWS: ${systemState.totalWS}\nTotal Blocks: ${this.mitigatedCount}`
      : `CPU: ${cpuUsage}%\nMemory: ${memUsage}GB\nTotal Blocks: ${this.mitigatedCount}`;

    const embed = new EmbedBuilder()
      .setTitle('🛡️ DDoS Attack Detected!')
      .setDescription('High volume of malicious traffic identified.\nStarting automated mitigation...')
      .addFields(
        { name: 'Top Abusers', value: topAbusers.map((a) => `${a.ip} — ${a.count} blocks (${a.primaryType})`).join('\n') || 'N/A', inline: false },
        { name: 'Block Reasons', value: blockTypesSummary, inline: true },
        { name: 'System Status', value: systemStatus, inline: true },
        { name: 'Attack Patterns', value: attackPatterns, inline: false }
      )
      .setColor('#ff0000')
      .setTimestamp();

    await this.sendLog(null, embed);

    this.attackEndTimer = setTimeout(() => this.endAttackAlert(), ATTACK_END_TIMEOUT);
  }

  async endAttackAlert() {
    if (!this.isUnderAttack) return;

    this.isUnderAttack = false;
    this.autoMitigationActive = false;
    this.attackVector = null;
    if (this.attackEndTimer) {
      clearTimeout(this.attackEndTimer);
      this.attackEndTimer = null;
    }

    const duration = Math.floor((Date.now() - this.attackStartTime) / 1000);
    const topAbusers = this.getTopAbusers(5);
    const mem = process.memoryUsage();
    const memUsage = (mem.heapUsed / 1024 / 1024 / 1024).toFixed(2);

    const mitigationSummary = this.mitigationActions.length > 0 ? this.mitigationActions.join(', ') : 'Standard protections';

    const embed = new EmbedBuilder()
      .setTitle('✅ Attack Mitigated Successfully')
      .setDescription(
        `DDoS attack neutralized after ${duration} seconds.\nTotal requests blocked: **${this.mitigatedCount.toLocaleString()}**\nMitigation actions: ${mitigationSummary}`
      )
      .addFields(
        { name: 'Top Attackers', value: topAbusers.map((a) => `${a.ip} — ${a.count} blocks`).join('\n') || 'N/A' },
        { name: 'Memory Status', value: `${memUsage}GB heap used`, inline: true }
      )
      .setColor('#00ff00')
      .setTimestamp();

    await this.sendLog(null, embed);

    this.mitigationActions = [];
  }

  cleanupOldEntries() {
    const now = Date.now();

    for (const [ip, data] of this.ipBlocks.entries()) {
      data.blocks = data.blocks.filter((t) => now - t < 60000);
      if (data.blocks.length === 0) {
        this.ipBlocks.delete(ip);
      }
    }

    for (const [ip, hits] of this.challengeHits.entries()) {
      const recent = hits.filter((t) => now - t < 30000);
      if (recent.length === 0) {
        this.challengeHits.delete(ip);
      } else {
        this.challengeHits.set(ip, recent);
      }
    }

    for (const [ip, data] of this.ipRequests.entries()) {
      if (now - data.lastSeen > 60000) {
        this.ipRequests.delete(ip);
      } else {
        if (data.wsHistory) {
          data.wsHistory = data.wsHistory.filter((t) => now - t < 60000);
        }
      }
    }

    this.recentBlocks = this.recentBlocks.filter((t) => now - t < 60000);

    if (this.wsFlushHistory.length > 100) {
      this.wsFlushHistory = this.wsFlushHistory.slice(-50);
    }
  }

  trackRequest(ip) {
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return;

    const now = Date.now();
    const data = this.ipRequests.get(ip) || { count: 0, lastSeen: now, blocks: 0, firstSeen: now, burstCount: 0, lastBurst: now };
    data.count++;
    data.lastSeen = now;

    if (now - data.lastBurst < 1000) {
      data.burstCount++;
      if (data.burstCount > 100) {
        this.incrementBlocked(ip, 'burst_attack');
        data.burstCount = 0;
      }
    } else {
      data.burstCount = 1;
      data.lastBurst = now;
    }

    this.ipRequests.set(ip, data);

    const timeWindow = now - data.firstSeen;
    const rate = timeWindow > 0 ? data.count / (timeWindow / 1000) : 0;

    if (data.count > 50000 || rate > 10000) {
      this.incrementBlocked(ip, 'request_flood');
    }
  }

  trackWS(ip, delta) {
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return;

    const existing = this.ipRequests.get(ip);
    const current = existing?.ws || 0;
    const updated = Math.max(0, current + delta);

    const data = existing || { count: 0, lastSeen: Date.now(), ws: 0, wsHistory: [] };
    data.ws = updated;
    data.lastSeen = Date.now();

    if (!data.wsHistory) {
      data.wsHistory = [];
    }

    if (delta > 0) {
      data.wsHistory.push(Date.now());
      data.wsHistory = data.wsHistory.filter((t) => Date.now() - t < 60000);

      if (data.wsHistory.length > 500) {
        this.incrementBlocked(ip, 'ws_burst');
        data.wsHistory = [];
      }
    }

    this.ipRequests.set(ip, data);

    if (delta < 0) return;

    const cpuUsage = this.getCpuUsage();
    const mem = process.memoryUsage();

    if (updated > 500 && (cpuUsage > CPU_THRESHOLD || mem.heapUsed > MEMORY_CRITICAL)) {
      this.incrementBlocked(ip, 'ws_flood');
    }
  }

  monitorMemory() {
    const mem = process.memoryUsage();
    const heapUsed = mem.heapUsed;
    const rss = mem.rss;
    const active = heapUsed > MEMORY_CRITICAL || rss > MEMORY_THRESHOLD;

    this.memoryStats = { heapUsed, rss, active, timestamp: Date.now() };

    if (active && !this.memoryStats.active) {
      this.sendLog('🚨 Memory pressure detected!', null);
    }

    if (heapUsed > MEMORY_THRESHOLD * 1.2) {
      this.sendLog(`💀 CRITICAL: Memory usage at ${(heapUsed / 1024 / 1024 / 1024).toFixed(2)}GB`, null);
      if (global.gc) {
        global.gc();
        this.sendLog('🧹 Forced garbage collection', null);
      }
    }
  }

  detectAttackPatterns() {
    const now = Date.now();
    const patterns = new Map();

    for (const [ip, data] of this.ipBlocks.entries()) {
      const recent = data.blocks.filter((t) => now - t < PATTERN_DETECTION_WINDOW);
      if (recent.length < ATTACK_PATTERN_THRESHOLD) continue;

      const types = data.types;
      const topType = Object.entries(types).sort((a, b) => b[1] - a[1])[0]?.[0] || 'unknown';

      const patternKey = `${topType}:${recent.length}`;
      if (!patterns.has(patternKey)) {
        patterns.set(patternKey, { type: topType, count: 0, ips: [] });
      }
      const pattern = patterns.get(patternKey);
      pattern.count += recent.length;
      pattern.ips.push(ip);
    }

    for (const [key, pattern] of patterns.entries()) {
      if (pattern.count > 200 && pattern.ips.length > 10) {
        this.attackPatterns.set(key, { ...pattern, detected: now });

        if (!this.isUnderAttack && !this.startupGracePeriod) {
          this.autoMitigationActive = true;
          this.attackVector = pattern.type;
          this.sendLog(`🔍 Attack pattern detected: ${pattern.type} (${pattern.count} blocks from ${pattern.ips.length} IPs)`, null);
        }
      }
    }

    this.attackPatterns.forEach((pattern, key) => {
      if (now - pattern.detected > 600000) {
        this.attackPatterns.delete(key);
      }
    });
  }

  trackMemoryPressure(ip) {
    const now = Date.now();
    const data = this.ipRequests.get(ip) || { count: 0, lastSeen: now, memoryPressure: 0 };
    data.memoryPressure = (data.memoryPressure || 0) + 1;
    this.ipRequests.set(ip, data);

    if (data.memoryPressure > 10) {
      this.incrementBlocked(ip, 'memory_abuse');
    }
  }

  updateMemoryStats(mem, pressure, activeRequests) {
    this.memoryStats = {
      heapUsed: mem.heapUsed,
      rss: mem.rss,
      heapTotal: mem.heapTotal,
      external: mem.external,
      arrayBuffers: mem.arrayBuffers,
      active: pressure,
      activeRequests,
      timestamp: Date.now()
    };

    if (pressure && this.isUnderAttack && !this.mitigationActions.includes('memory_mitigation')) {
      this.mitigationActions.push('memory_mitigation');
      this.sendLog(`⚡ Memory mitigation activated (${(mem.heapUsed / 1024 / 1024 / 1024).toFixed(2)}GB used)`, null);
    }
  }

  registerCommands(client) {
    client.once('ready', () => {
      const commands = [
        { name: 'channel-setup', description: 'Set this channel as DDoS security log' },
        { name: 'test-attack', description: 'Simulate a DDoS attack to test the system' },
        { name: 'security-stats', description: 'View current security statistics' },
        { name: 'memory-status', description: 'View current memory usage and statistics' },
        { name: 'kill-switch', description: 'Emergency shutdown of the server' },
        { name: 'startup', description: 'Deactivate kill switch and allow server to run' }
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
          embeds: [
            new EmbedBuilder()
              .setTitle('✅ Security Log Channel Set')
              .setDescription('This channel will now receive live DDoS alerts and mitigation updates.')
              .setColor('#00ff00')
          ]
        });
      }

      if (interaction.commandName === 'test-attack') {
        await interaction.reply({ content: '🧪 Simulating DDoS attack for testing...', ephemeral: false });

        for (let i = 0; i < 100; i++) {
          this.incrementBlocked(`192.168.1.${i % 10}`, i % 3 === 0 ? 'pow_fail' : i % 3 === 1 ? 'rate_limit' : 'ws_cap');
          if (i % 10 === 0) await new Promise((r) => setTimeout(r, 100));
        }

        setTimeout(() => this.endAttackAlert(), 15000);
      }

      if (interaction.commandName === 'security-stats') {
        const topAbusers = this.getTopAbusers(10);
        const blockRate = this.getRecentBlockRate();
        const cpuUsage = this.getCpuUsage().toFixed(1);
        const { totalHits, uniqueIps } = this.getChallengeSpike();
        const mem = process.memoryUsage();
        const heapUsed = (mem.heapUsed / 1024 / 1024 / 1024).toFixed(2);
        const rss = (mem.rss / 1024 / 1024 / 1024).toFixed(2);

        const systemState = interaction.client.systemState || {};
        const powDifficulty = systemState.currentPowDifficulty || 16;
        const requestRate = systemState.requestRatePerMinute || 0;

        let statusText = '🟩 Normal';
        let statusColor = '#00ff00';

        if (this.killSwitchActive) {
          statusText = '🔴 KILL SWITCH ACTIVE';
          statusColor = '#ff0000';
        } else if (this.isUnderAttack) {
          statusText = '🟥 Under Attack';
          statusColor = '#ff0000';
        } else if (systemState.state === 'BUSY') {
          statusText = '🟡 Busy (High Legitimate Load)';
          statusColor = '#ffaa00';
        }

        const embed = new EmbedBuilder()
          .setTitle('📊 Security Statistics')
          .addFields(
            { name: 'Status', value: statusText, inline: true },
            { name: 'CPU Usage', value: `${cpuUsage}%`, inline: true },
            { name: 'PoW Difficulty', value: `${powDifficulty}`, inline: true },
            { name: 'Requests/min', value: `${Math.round(requestRate)}`, inline: true },
            { name: 'Block Rate', value: `${blockRate}/min`, inline: true },
            { name: 'Memory (Heap)', value: `${heapUsed}GB`, inline: true },
            { name: 'Memory (RSS)', value: `${rss}GB`, inline: true },
            { name: 'Total Blocks', value: this.mitigatedCount.toLocaleString(), inline: true },
            { name: 'Challenge Hits', value: `${totalHits} from ${uniqueIps} IPs`, inline: true },
            { name: 'Attack Patterns', value: this.attackPatterns.size.toString(), inline: true },
            { name: 'Top Abusers', value: topAbusers.map((a) => `${a.ip}: ${a.count} (${a.primaryType})`).join('\n') || 'None', inline: false }
          )
          .setColor(statusColor)
          .setTimestamp();

        await interaction.reply({ embeds: [embed], ephemeral: true });
      }

      if (interaction.commandName === 'memory-status') {
        const mem = process.memoryUsage();
        const heapUsed = (mem.heapUsed / 1024 / 1024 / 1024).toFixed(2);
        const heapTotal = (mem.heapTotal / 1024 / 1024 / 1024).toFixed(2);
        const rss = (mem.rss / 1024 / 1024 / 1024).toFixed(2);
        const external = (mem.external / 1024 / 1024 / 1024).toFixed(2);

        const status = this.memoryStats.active ? '🟥 High Pressure' : '🟩 Normal';

        const embed = new EmbedBuilder()
          .setTitle('💾 Memory Status')
          .addFields(
            { name: 'Status', value: status, inline: true },
            { name: 'Heap Used', value: `${heapUsed}GB`, inline: true },
            { name: 'Heap Total', value: `${heapTotal}GB`, inline: true },
            { name: 'RSS', value: `${rss}GB`, inline: true },
            { name: 'External', value: `${external}GB`, inline: true },
            { name: 'Active Requests', value: this.memoryStats.activeRequests?.toString() || 'N/A', inline: true }
          )
          .setColor(this.memoryStats.active ? '#ff0000' : '#00ff00')
          .setTimestamp();

        await interaction.reply({ embeds: [embed], ephemeral: true });
      }

      if (interaction.commandName === 'kill-switch') {
        this.killSwitchActive = true;
        
        const embed = new EmbedBuilder()
          .setTitle('🔴 KILL SWITCH ACTIVATED')
          .setDescription('Server is now in emergency shutdown mode.\nAll incoming connections will be rejected.\nUse /startup to restore normal operations.')
          .setColor('#ff0000')
          .setTimestamp();

        await interaction.reply({ embeds: [embed] });
        await this.sendLog(null, embed);

        setTimeout(() => {
          if (this.killSwitchActive) {
            console.log('KILL SWITCH: Terminating process...');
            process.exit(0);
          }
        }, 5000);
      }

      if (interaction.commandName === 'startup') {
        if (!this.killSwitchActive) {
          return interaction.reply({ 
            content: '✅ Kill switch is not active. Server is running normally.', 
            ephemeral: true 
          });
        }

        this.killSwitchActive = false;
        
        const embed = new EmbedBuilder()
          .setTitle('✅ Server Restored')
          .setDescription('Kill switch deactivated.\nServer is now accepting connections normally.')
          .setColor('#00ff00')
          .setTimestamp();

        await interaction.reply({ embeds: [embed] });
        await this.sendLog(null, embed);
      }
    });
  }

  isKillSwitchActive() {
    return this.killSwitchActive;
  }
}

export const ddosShield = (client) => {
  return new DDoSShield(client);
};
