// Edge-AI Sentinel NIPS Dashboard JavaScript with Chart.js

const API_BASE = '/api' || '';
let charts = {}; // Store chart instances for updates
let knownBlockedIps = null; // IPs already shown, to highlight new blocks

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('Dashboard initialized');
    updateDashboard();
    // Refresh data every 5 seconds for real-time updates
    setInterval(updateDashboard, 5000);
    // Firewall blocks refresh faster: the examiner should see a block appear
    // within moments of the attack starting
    updateBlockedThreats();
    setInterval(updateBlockedThreats, 2000);
});

// Main update function
async function updateDashboard() {
    try {
        // Update health status
        await updateHealthStatus();
        // Update statistics with charts
        await updateStatistics();
        // Update recent alerts
        await updateRecentAlerts();
        // Update last refresh time
        updateLastRefreshTime();
    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}

// Update health status
async function updateHealthStatus() {
    try {
        const response = await fetch('/health');
        const data = await response.json();
        
        const statusLight = document.getElementById('status-light');
        const statusText = document.getElementById('status-text');
        const statusTime = document.getElementById('status-time');
        
        if (data.status === 'healthy') {
            statusLight.classList.add('healthy');
            statusLight.classList.remove('unhealthy');
            statusText.textContent = '✓ System Healthy & Monitoring';
            statusText.classList.add('success');
        } else {
            statusLight.classList.remove('healthy');
            statusLight.classList.add('unhealthy');
            statusText.textContent = '✗ System Unhealthy';
            statusText.classList.add('danger');
        }
        
        const timestamp = new Date(data.timestamp);
        statusTime.textContent = `Last checked: ${timestamp.toLocaleTimeString()}`;
    } catch (error) {
        console.error('Error fetching health:', error);
        document.getElementById('status-text').textContent = '⚠ Unable to connect';
    }
}

// Update statistics with chart data
async function updateStatistics() {
    try {
        const response = await fetch('/stats');
        const data = await response.json();
        
        // Update stat cards
        document.getElementById('total-alerts').textContent = 
            data.total_attack_alerts ? data.total_attack_alerts.toLocaleString() : '0';
        
        document.getElementById('alerts-last-hour').textContent = 
            data.alerts_last_hour ? data.alerts_last_hour.toLocaleString() : '0';
        
        document.getElementById('severity-high').textContent = 
            data.severity_distribution.high || '0';
        
        document.getElementById('severity-medium').textContent = 
            data.severity_distribution.medium || '0';
        
        // Update charts
        updateAttackTypeChart(data.attack_type_distribution || {});
        updateSeverityChart(data.severity_distribution || {});
        updateProtocolChart(data.protocol_distribution || {});
    } catch (error) {
        console.error('Error fetching statistics:', error);
    }
}

// Update Attack Type Distribution Chart
function updateAttackTypeChart(attackTypes) {
    const ctx = document.getElementById('attackTypeChart');
    if (!ctx) return;
    
    const labels = Object.keys(attackTypes);
    const data = Object.values(attackTypes);
    
    // Destroy existing chart if it exists
    if (charts.attackType) {
        charts.attackType.destroy();
    }
    
    charts.attackType = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.length > 0 ? labels : ['No Data'],
            datasets: [{
                data: labels.length > 0 ? data : [1],
                backgroundColor: [
                    '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                    '#FF9F40', '#FF6384', '#C9CBCF', '#4BC0C0', '#FF6384'
                ],
                borderColor: '#ffffff',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                }
            }
        }
    });
}

// Update Severity Chart
function updateSeverityChart(severity) {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    
    // Destroy existing chart if it exists
    if (charts.severity) {
        charts.severity.destroy();
    }
    
    charts.severity = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['High (≥80%)', 'Medium (50-80%)', 'Low (<50%)'],
            datasets: [{
                label: 'Attack Count',
                data: [
                    severity.high || 0,
                    severity.medium || 0,
                    severity.low || 0
                ],
                backgroundColor: [
                    '#cc0000',
                    '#ff9900',
                    '#ffcc00'
                ],
                borderColor: [
                    '#990000',
                    '#cc6600',
                    '#ccaa00'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Update Protocol Distribution Chart
function updateProtocolChart(protocols) {
    const ctx = document.getElementById('protocolChart');
    if (!ctx) return;
    
    const labels = Object.keys(protocols);
    const data = Object.values(protocols);
    
    // Destroy existing chart if it exists
    if (charts.protocol) {
        charts.protocol.destroy();
    }
    
    charts.protocol = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: labels.length > 0 ? labels : ['No Data'],
            datasets: [{
                data: labels.length > 0 ? data : [1],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)',
                    'rgba(75, 192, 192, 0.7)',
                    'rgba(153, 102, 255, 0.7)'
                ],
                borderColor: [
                    '#cc0033',
                    '#0066cc',
                    '#ccaa00',
                    '#00aa99',
                    '#6600cc'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                }
            }
        }
    });
}

// Update recent alerts table
async function updateRecentAlerts() {
    try {
        const response = await fetch('/alerts?limit=50');
        const data = await response.json();
        
        const tbody = document.getElementById('alerts-tbody');
        
        if (!data.alerts || data.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="loading">No attacks detected yet - system is secure</td></tr>';
            return;
        }

        let html = '';
        data.alerts.forEach(alert => {
            const timestamp = new Date(alert.timestamp);
            const confidence = parseFloat(alert.confidence * 100).toFixed(1);

            let severityClass = 'success';
            if (confidence >= 80) severityClass = 'danger';
            else if (confidence >= 50) severityClass = 'warning';

            html += `
                <tr>
                    <td>${escapeHtml(timestamp.toLocaleString())}</td>
                    <td><code>${escapeHtml(alert.src_ip)}</code></td>
                    <td><code>${escapeHtml(alert.dst_ip)}</code></td>
                    <td>${escapeHtml(alert.protocol || 'N/A')}</td>
                    <td><strong>${escapeHtml(alert.attack_type)}</strong></td>
                    <td>${engineTag(alert.detector)}</td>
                    <td>
                        <span class="confidence-badge ${severityClass}" style="background-color: ${getConfidenceColor(confidence)}">
                            ${confidence}%
                        </span>
                    </td>
                    <td>${statusBadge(alert.status)}</td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    } catch (error) {
        console.error('Error fetching recent alerts:', error);
        document.getElementById('alerts-tbody').innerHTML =
            '<tr><td colspan="8" class="loading">Error loading alerts</td></tr>';
    }
}

// ── NIPS: active firewall blocks ─────────────────────────────
async function updateBlockedThreats() {
    try {
        const response = await fetch('/blocked_threats');
        const data = await response.json();

        document.getElementById('blocked-count').textContent = data.count || 0;
        document.getElementById('dropped-total').textContent =
            data.total_dropped_packets == null ? '-' : data.total_dropped_packets.toLocaleString();
        document.getElementById('fw-chain').textContent = data.chain || '-';
        renderModeBadge(data.mode, data.firewall_visible);

        const tbody = document.getElementById('blocked-tbody');
        const blocks = data.blocked || [];
        const seenBefore = knownBlockedIps;
        knownBlockedIps = new Set(blocks.map(b => b.ip));

        if (blocks.length === 0) {
            const idle = data.mode === 'enforce'
                ? 'No active blocks - network is clean'
                : 'No active blocks - prevention is not enforcing';
            tbody.innerHTML = `<tr><td colspan="9" class="loading">${idle}</td></tr>`;
            return;
        }

        tbody.innerHTML = blocks.map(block => {
            // Highlight rows that appeared since the previous refresh
            const isNew = seenBefore !== null && !seenBefore.has(block.ip);
            const confidence = block.confidence == null
                ? '-' : `${(block.confidence * 100).toFixed(1)}%`;
            const latency = block.block_latency_ms == null
                ? '-' : `${block.block_latency_ms.toFixed(1)} ms`;
            const dropped = block.dropped_packets == null
                ? '-' : block.dropped_packets.toLocaleString();
            return `
                <tr class="${isNew ? 'new-block' : ''}">
                    <td><code class="attacker-ip">${escapeHtml(block.ip)}</code></td>
                    <td><code>${escapeHtml(block.target_ip || '-')}</code></td>
                    <td><strong>${escapeHtml(block.attack_type)}</strong></td>
                    <td>${engineTag(block.detector)}</td>
                    <td>${confidence}</td>
                    <td>${escapeHtml(block.blocked_at)}</td>
                    <td>${latency}</td>
                    <td>${dropped}</td>
                    <td>${kernelRuleBadge(block.enforced)}</td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error fetching blocked threats:', error);
    }
}

function renderModeBadge(mode, firewallVisible) {
    const badge = document.getElementById('nips-mode-badge');
    const note = document.getElementById('fw-note');
    badge.className = 'mode-badge';
    if (mode === 'enforce') {
        badge.classList.add('mode-enforce');
        badge.textContent = 'Prevention: ENFORCING';
        note.textContent = firewallVisible
            ? 'Attackers are dropped by the Linux kernel (iptables) the moment they are classified.'
            : 'Kernel firewall state is not readable by the dashboard (run it as root on the Pi to verify rules and drop counters).';
    } else if (mode === 'dry-run') {
        badge.classList.add('mode-dry-run');
        badge.textContent = 'Prevention: DRY-RUN';
        note.textContent = 'Dry-run: attacks are flagged as DRY_RUN but no traffic is blocked.';
    } else {
        badge.classList.add('mode-off');
        badge.textContent = 'Prevention: OFF';
        note.textContent = 'Prevention is off: the system only detects (NIDS mode).';
    }
}

function statusBadge(status) {
    const value = status || 'DETECTED';
    const css = value.toLowerCase().replace(/_/g, '-');
    return `<span class="status-badge status-${escapeHtml(css)}">${escapeHtml(value.replace(/_/g, ' '))}</span>`;
}

function engineTag(detector) {
    const value = (detector || 'UNKNOWN').toUpperCase();
    return `<span class="engine-tag engine-${escapeHtml(value.toLowerCase())}">${escapeHtml(value)}</span>`;
}

function kernelRuleBadge(enforced) {
    if (enforced === true) return '<span class="status-badge status-blocked">ACTIVE</span>';
    if (enforced === false) return '<span class="status-badge status-block-failed">MISSING</span>';
    return '<span class="status-badge status-unknown">UNVERIFIED</span>';
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Get color based on confidence level
function getConfidenceColor(confidence) {
    if (confidence >= 80) return '#cc0000'; // Red - High
    if (confidence >= 50) return '#ff9900'; // Orange - Medium
    if (confidence >= 20) return '#ffcc00'; // Yellow - Low
    return '#00cc66'; // Green - Very Low
}

// Update last refresh time
function updateLastRefreshTime() {
    const now = new Date();
    document.getElementById('last-update').textContent = now.toLocaleTimeString();
}
