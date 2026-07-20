document.addEventListener('DOMContentLoaded', () => {
    let isPaused = false;
    let lastTimestamp = 0;
    const updateIntervalMs = 1000;
    
    // State
    const allPackets = [];
    const allSessions = [];
    const allAlerts = [];
    let packetIndexCounter = 1;
    let selectedPacketIndex = null;
    let selectedPacket = null;
    
    const packetTable = document.getElementById('packet-tbody');
    const sessionTable = document.getElementById('session-tbody');
    const alertTable = document.getElementById('alert-tbody');
    
    // Tabs
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });

    // Inspector Payload tabs click
    const pTabBtns = document.querySelectorAll('.payload-tab-btn');
    pTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            pTabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.payload-tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(btn.dataset.ptab).classList.add('active');
        });
    });
    
    // Stats elements
    const elTotal = document.getElementById('stat-total');
    const elRate = document.getElementById('stat-rate');
    const elBytes = document.getElementById('stat-bytes');
    const elProtocol = document.getElementById('stat-protocol');
    const elAlerts = document.getElementById('stat-alerts');
    const elEngine = document.getElementById('stat-engine');
    const engineCard = document.getElementById('engine-status-card');
    const elTi = document.getElementById('stat-ti');
    const tiCard = document.getElementById('ti-status-card');
    const statusIndicator = document.querySelector('.status-indicator');
    const statusText = document.getElementById('status-text');
    
    // Filters
    const filterIp = document.getElementById('filter-ip');
    const filterProtocol = document.getElementById('filter-protocol');
    const filterPort = document.getElementById('filter-port');
    const btnClear = document.getElementById('btn-clear-filters');
    const btnPause = document.getElementById('btn-pause');
    const btnClearData = document.getElementById('btn-clear-data');

    // Threat Intel elements
    const btnUpdateIntel = document.getElementById('btn-update-intel');
    const intelIpCount = document.getElementById('intel-ip-count');
    const intelDomainCount = document.getElementById('intel-domain-count');
    const intelLastUpdated = document.getElementById('intel-last-updated');
    const intelAlertsTable = document.getElementById('intel-alerts-tbody');

    // Filter event listeners
    [filterIp, filterProtocol, filterPort].forEach(el => {
        el.addEventListener('input', updateTable);
    });
    
    btnClear.addEventListener('click', () => {
        filterIp.value = '';
        filterProtocol.value = '';
        filterPort.value = '';
        updateTable();
    });

    btnPause.addEventListener('click', () => {
        isPaused = !isPaused;
        if (isPaused) {
            btnPause.textContent = "Resume Feed";
            btnPause.classList.add('paused');
            statusIndicator.classList.add('paused');
            statusText.textContent = "Capture Paused";
        } else {
            btnPause.textContent = "Pause Feed";
            btnPause.classList.remove('paused');
            statusIndicator.classList.remove('paused');
            statusText.textContent = "Live Capture";
        }
    });

    btnClearData.addEventListener('click', async () => {
        try {
            await fetch('/api/clear', { method: 'POST' });
            allPackets.length = 0;
            allSessions.length = 0;
            allAlerts.length = 0;
            packetIndexCounter = 1;
            lastTimestamp = 0;
            lastAlertTimestamp = 0;
            
            // Clear inspector
            selectedPacketIndex = null;
            selectedPacket = null;
            showPacketInspector(null);
            
            updateTable();
            updateSessionTable();
            updateAlertTable();
            updateThreatIntelAlertsTable();
            computeStats();
            elAlerts.textContent = 0;
        } catch (err) {
            console.error("Failed to clear data:", err);
        }
    });

    if (btnUpdateIntel) {
        btnUpdateIntel.addEventListener('click', async () => {
            try {
                btnUpdateIntel.disabled = true;
                btnUpdateIntel.textContent = "Updating feeds...";
                
                const res = await fetch('/api/threat_intel/update', { method: 'POST' });
                if (res.ok) {
                    let attempts = 0;
                    const pollInterval = setInterval(async () => {
                        const status = await fetchThreatIntelStatus();
                        attempts++;
                        if (!status || !status.is_updating || attempts > 30) {
                            clearInterval(pollInterval);
                            btnUpdateIntel.disabled = false;
                            btnUpdateIntel.textContent = "Update Feeds";
                        }
                    }, 1000);
                } else {
                    btnUpdateIntel.disabled = false;
                    btnUpdateIntel.textContent = "Update Feeds";
                }
            } catch (err) {
                console.error("Failed to start feed update:", err);
                btnUpdateIntel.disabled = false;
                btnUpdateIntel.textContent = "Update Feeds";
            }
        });
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    function getBadgeClass(proto) {
        proto = proto.toLowerCase();
        if (['tcp', 'udp', 'icmp', 'dns', 'arp'].includes(proto)) {
            return proto;
        }
        if (proto.includes('http')) return 'http';
        return 'default';
    }

    function computeStats() {
        if (allPackets.length === 0) return;
        
        elTotal.textContent = allPackets.length;
        
        // Total Bytes
        const totalBytes = allPackets.reduce((sum, p) => sum + (p.length || 0), 0);
        elBytes.innerHTML = formatBytes(totalBytes).replace(' ', ' <span class="unit">') + '</span>';
        
        // Rate (packets in last 5 seconds based on real time)
        const now = Date.now() / 1000;
        const recentPackets = allPackets.filter(p => (now - p.timestamp) <= 5);
        const rate = recentPackets.length > 0 ? recentPackets.length / 5.0 : 0;
        elRate.innerHTML = rate.toFixed(1) + ' <span class="unit">pkts/s</span>';
        
        // Top Protocol
        const protoCounts = {};
        allPackets.forEach(p => {
            const proto = p.layers && p.layers.length > 0 ? p.layers[p.layers.length-1].layer : "Unknown";
            protoCounts[proto] = (protoCounts[proto] || 0) + 1;
        });
        
        const topProto = Object.keys(protoCounts).reduce((a, b) => protoCounts[a] > protoCounts[b] ? a : b, "-");
        elProtocol.textContent = topProto;
    }

    function formatTime(timestamp) {
        const d = new Date(timestamp * 1000);
        const pad = (num, size) => num.toString().padStart(size, '0');
        return `${pad(d.getHours(), 2)}:${pad(d.getMinutes(), 2)}:${pad(d.getSeconds(), 2)}.${pad(d.getMilliseconds(), 3)}`;
    }
    
    function getPrimaryInfo(packet) {
        const layers = packet.layers || [];
        if (layers.length === 0) return { src: "-", dst: "-", proto: "-", info: "-", layers: [] };
        
        let src = "-";
        let dst = "-";
        let proto = "-";
        let info = packet.summary || "-";
        
        // Extract IPs
        const ipLayer = layers.find(l => l.layer === "IPv4" || l.layer === "IPv6");
        if (ipLayer) {
            src = ipLayer.src_ip;
            dst = ipLayer.dst_ip;
        } else {
            const ethLayer = layers.find(l => l.layer === "Ethernet");
            if (ethLayer) {
                src = ethLayer.src_mac;
                dst = ethLayer.dst_mac;
            }
        }
        
        // Extract high level proto
        proto = layers[layers.length - 1].layer;
        
        return { src, dst, proto, info, layers };
    }

    function checkFilters(packetDetails) {
        const ipF = filterIp.value.toLowerCase().trim();
        const protoF = filterProtocol.value.toLowerCase();
        const portF = filterPort.value.toLowerCase().trim();
        
        if (ipF && !packetDetails.src.toLowerCase().includes(ipF) && !packetDetails.dst.toLowerCase().includes(ipF)) {
            return false;
        }
        if (protoF && !packetDetails.proto.toLowerCase().includes(protoF)) {
            return false;
        }
        if (portF) {
            let hasPort = false;
            for (const layer of packetDetails.layers) {
                if ((layer.src_port && layer.src_port.toString() === portF) || 
                    (layer.dst_port && layer.dst_port.toString() === portF)) {
                    hasPort = true;
                    break;
                }
            }
            if (!hasPort) return false;
        }
        
        return true;
    }

    function updateTable() {
        packetTable.innerHTML = '';
        
        const filteredPackets = [];
        for (let i = allPackets.length - 1; i >= 0; i--) {
            const p = allPackets[i];
            const details = getPrimaryInfo(p);
            
            if (checkFilters(details)) {
                filteredPackets.push({p, details, index: p._globalIndex});
            }
            
            if (filteredPackets.length >= 100) break;
        }
        
        filteredPackets.forEach(({p, details, index}) => {
            const tr = document.createElement('tr');
            tr.className = 'row-enter';
            if (selectedPacketIndex === index) {
                tr.classList.add('selected');
            }
            tr.innerHTML = `
                <td>${index}</td>
                <td>${formatTime(p.timestamp)}</td>
                <td>${details.src}</td>
                <td>${details.dst}</td>
                <td><span class="badge ${getBadgeClass(details.proto)}">${details.proto}</span></td>
                <td>${p.length}</td>
                <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px;" title="${details.info}">${details.info}</td>
            `;
            
            tr.addEventListener('click', () => {
                document.querySelectorAll('#packet-table tbody tr').forEach(r => r.classList.remove('selected'));
                tr.classList.add('selected');
                selectedPacketIndex = index;
                selectedPacket = p;
                showPacketInspector(p);
            });
            
            packetTable.appendChild(tr);
        });
    }

    function showPacketInspector(packet) {
        const placeholder = document.getElementById('inspector-placeholder');
        const content = document.getElementById('inspector-content');
        
        if (!packet) {
            placeholder.classList.remove('hidden');
            content.classList.add('hidden');
            return;
        }
        
        placeholder.classList.add('hidden');
        content.classList.remove('hidden');
        
        const details = getPrimaryInfo(packet);
        
        // Header
        document.getElementById('inspect-proto').textContent = details.proto;
        document.getElementById('inspect-proto').className = `badge ${getBadgeClass(details.proto)}`;
        document.getElementById('inspect-time').textContent = formatTime(packet.timestamp);
        
        // DPI/Threat Intel Alerts
        const alertsDiv = document.getElementById('inspect-dpi-alerts');
        alertsDiv.innerHTML = '';
        
        const correlatedAlerts = allAlerts.filter(a => {
            const timeDiff = Math.abs(a.timestamp - packet.timestamp);
            return timeDiff < 1.5 && a.src_ip === details.src;
        });
        
        if (correlatedAlerts.length > 0) {
            alertsDiv.classList.remove('hidden');
            correlatedAlerts.forEach(a => {
                const div = document.createElement('div');
                div.className = 'inspect-dpi-alert';
                div.innerHTML = `
                    <span class="inspect-dpi-alert-dot"></span>
                    <span><strong>[${a.severity}] ${a.rule_name}</strong>: ${a.description}</span>
                `;
                alertsDiv.appendChild(div);
            });
        } else {
            alertsDiv.classList.add('hidden');
        }
        
        // Layer Tree
        const layersContainer = document.getElementById('inspect-layers');
        layersContainer.innerHTML = '';
        
        if (packet.layers && packet.layers.length > 0) {
            packet.layers.forEach((layer, idx) => {
                const node = document.createElement('div');
                node.className = 'layer-node';
                
                const title = document.createElement('div');
                title.className = 'layer-title';
                title.innerHTML = `
                    <span>${layer.layer} Layer</span>
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="transform: rotate(90deg); transition: transform 0.2s;"><path d="m9 18 6-6-6-6"/></svg>
                `;
                
                const fields = document.createElement('div');
                fields.className = 'layer-fields';
                
                let fieldCount = 0;
                for (const [key, val] of Object.entries(layer)) {
                    if (key === 'layer') continue;
                    const fieldDiv = document.createElement('div');
                    fieldDiv.className = 'layer-field';
                    const keyFormatted = key.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                    fieldDiv.innerHTML = `<span class="field-name">${keyFormatted}:</span> ${val}`;
                    fields.appendChild(fieldDiv);
                    fieldCount++;
                }
                
                if (fieldCount === 0) {
                    fields.innerHTML = '<div class="layer-field" style="color: var(--text-secondary);">No parameters</div>';
                }
                
                title.addEventListener('click', () => {
                    const isHidden = fields.classList.toggle('hidden');
                    const svg = title.querySelector('svg');
                    if (isHidden) {
                        svg.style.transform = 'rotate(0deg)';
                    } else {
                        svg.style.transform = 'rotate(90deg)';
                    }
                });
                
                node.appendChild(title);
                node.appendChild(fields);
                layersContainer.appendChild(node);
            });
        } else {
            layersContainer.innerHTML = '<div style="color: var(--text-secondary); font-size: 0.9rem;">No layers parsed</div>';
        }
        
        // Hex / Decoded Tab values
        document.getElementById('inspect-hexdump').textContent = packet.payload_hexdump || "No payload data present in packet headers.";
        document.getElementById('inspect-decoded').textContent = packet.payload || "No payload data present in packet headers.";
    }

    async function fetchPackets() {
        if (isPaused) return;
        
        try {
            const res = await fetch(`/api/packets?since=${lastTimestamp}`);
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.packets && data.packets.length > 0) {
                lastTimestamp = data.packets[data.packets.length - 1].timestamp;
                
                data.packets.forEach(p => {
                    p._globalIndex = packetIndexCounter++;
                    allPackets.push(p);
                });
                
                if (allPackets.length > 10000) {
                    allPackets.splice(0, allPackets.length - 10000);
                }
                
                computeStats();
                updateTable();
            } else {
                computeStats();
            }
        } catch (err) {
            console.error("Failed to fetch packets:", err);
        }
    }

    async function fetchSessions() {
        if (isPaused) return;
        try {
            const res = await fetch('/api/sessions');
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.sessions) {
                allSessions.length = 0;
                allSessions.push(...data.sessions);
                updateSessionTable();
            }
        } catch (err) {
            console.error("Failed to fetch sessions:", err);
        }
    }

    function updateSessionTable() {
        sessionTable.innerHTML = '';
        const sorted = allSessions.slice().sort((a, b) => b.last_time - a.last_time);
        
        sorted.forEach(s => {
            const tr = document.createElement('tr');
            tr.className = 'row-enter';
            const duration = Math.max(0, s.last_time - s.start_time).toFixed(2);
            
            tr.innerHTML = `
                <td><span class="badge ${getBadgeClass(s.protocol)}">${s.protocol}</span></td>
                <td><span class="badge state-${s.state.toLowerCase()}">${s.state}</span></td>
                <td>${s.endpoint_a}</td>
                <td>${s.endpoint_b}</td>
                <td>${s.packet_count}</td>
                <td>${formatBytes(s.total_bytes)}</td>
                <td>${duration}s</td>
            `;
            sessionTable.appendChild(tr);
        });
    }

    let lastAlertTimestamp = 0;
    
    async function fetchAlerts() {
        if (isPaused) return;
        try {
            const res = await fetch(`/api/alerts?since=${lastAlertTimestamp}`);
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.alerts && data.alerts.length > 0) {
                lastAlertTimestamp = data.alerts[data.alerts.length - 1].timestamp;
                allAlerts.push(...data.alerts);
                
                if (allAlerts.length > 1000) {
                    allAlerts.splice(0, allAlerts.length - 1000);
                }
                
                elAlerts.textContent = allAlerts.length;
                updateAlertTable();
                updateThreatIntelAlertsTable();
                
                if (selectedPacket) {
                    showPacketInspector(selectedPacket);
                }
            }
        } catch (err) {
            console.error("Failed to fetch alerts:", err);
        }
    }

    function updateAlertTable() {
        alertTable.innerHTML = '';
        const generalAlerts = allAlerts.filter(a => !a.rule_name.toLowerCase().includes('threatintel'));
        const sorted = generalAlerts.slice().sort((a, b) => b.timestamp - a.timestamp);
        
        sorted.forEach(a => {
            const tr = document.createElement('tr');
            tr.className = 'row-enter';
            tr.innerHTML = `
                <td>${formatTime(a.timestamp)}</td>
                <td><span class="badge severity-${a.severity.toLowerCase()}">${a.severity}</span></td>
                <td>${a.rule_name}</td>
                <td>${a.src_ip}</td>
                <td>${a.description}</td>
            `;
            alertTable.appendChild(tr);
        });
    }

    function updateThreatIntelAlertsTable() {
        if (!intelAlertsTable) return;
        
        const intelAlerts = allAlerts.filter(a => a.rule_name.toLowerCase().includes('threatintel'));
        
        if (intelAlerts.length === 0) {
            intelAlertsTable.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; color: var(--text-secondary);">No threat intelligence hits detected.</td>
                </tr>
            `;
            return;
        }
        
        intelAlertsTable.innerHTML = '';
        const sorted = intelAlerts.slice().sort((a, b) => b.timestamp - a.timestamp);
        
        sorted.forEach(a => {
            const tr = document.createElement('tr');
            tr.className = 'row-enter';
            tr.innerHTML = `
                <td>${formatTime(a.timestamp)}</td>
                <td><span class="badge severity-${a.severity.toLowerCase()}">${a.severity}</span></td>
                <td>${a.rule_name}</td>
                <td>${a.src_ip}</td>
                <td>${a.description}</td>
            `;
            intelAlertsTable.appendChild(tr);
        });
    }

    async function fetchStatus() {
        if (isPaused) return;
        try {
            const res = await fetch('/api/status');
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.anomaly_engine) {
                if (data.anomaly_engine.is_learning) {
                    elEngine.innerHTML = `Learning <span style="font-size: 0.8rem; color: var(--text-secondary);">(${data.anomaly_engine.progress}%)</span>`;
                    engineCard.style.borderTop = "2px solid var(--highlight)";
                } else {
                    elEngine.innerHTML = `Active <span style="font-size: 0.8rem; color: var(--text-secondary);">(Baseline)</span>`;
                    engineCard.style.borderTop = "2px solid #3b82f6";
                }
            }
            
            if (data.threat_intel) {
                if (data.threat_intel.is_updating) {
                    elTi.innerHTML = `Updating... <span style="font-size: 0.8rem; color: var(--text-secondary);">(from feeds)</span>`;
                    tiCard.style.borderTop = "2px solid var(--highlight)";
                } else {
                    const total = data.threat_intel.num_ips + data.threat_intel.num_domains;
                    elTi.innerHTML = `${total.toLocaleString()} <span style="font-size: 0.8rem; color: var(--text-secondary);">IOCs Loaded</span>`;
                    tiCard.style.borderTop = "2px solid #ef4444";
                }
            }
        } catch (err) {
            console.error("Failed to fetch status:", err);
        }
    }

    async function fetchThreatIntelStatus() {
        try {
            const res = await fetch('/api/threat_intel/status');
            if (!res.ok) return null;
            const data = await res.json();
            
            if (intelIpCount) intelIpCount.textContent = data.num_ips.toLocaleString();
            if (intelDomainCount) intelDomainCount.textContent = data.num_domains.toLocaleString();
            
            if (intelLastUpdated) {
                if (data.last_updated > 0) {
                    const date = new Date(data.last_updated * 1000);
                    intelLastUpdated.textContent = date.toLocaleTimeString() + " " + date.toLocaleDateString();
                } else {
                    intelLastUpdated.textContent = "Never (using seed lists)";
                }
            }
            
            return data;
        } catch (err) {
            console.error("Failed to fetch threat intel status:", err);
            return null;
        }
    }

    // Initial Threat Intel status fetch
    fetchThreatIntelStatus();

    // Polling Loop
    setInterval(() => {
        fetchPackets();
        fetchSessions();
        fetchAlerts();
        fetchStatus();
        fetchThreatIntelStatus();
    }, updateIntervalMs);
});
