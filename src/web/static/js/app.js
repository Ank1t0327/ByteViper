document.addEventListener('DOMContentLoaded', () => {
    let isPaused = false;
    let lastTimestamp = 0;
    const updateIntervalMs = 1000;
    
    // State
    const allPackets = [];
    const allSessions = [];
    const allAlerts = [];
    let packetIndexCounter = 1;
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
    
    // Stats elements
    const elTotal = document.getElementById('stat-total');
    const elRate = document.getElementById('stat-rate');
    const elBytes = document.getElementById('stat-bytes');
    const elProtocol = document.getElementById('stat-protocol');
    const elAlerts = document.getElementById('stat-alerts');
    const statusIndicator = document.querySelector('.status-indicator');
    const statusText = document.getElementById('status-text');
    
    // Filters
    const filterIp = document.getElementById('filter-ip');
    const filterProtocol = document.getElementById('filter-protocol');
    const filterPort = document.getElementById('filter-port');
    const btnClear = document.getElementById('btn-clear-filters');
    const btnPause = document.getElementById('btn-pause');

    const btnClearData = document.getElementById('btn-clear-data');

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
            updateTable();
            updateSessionTable();
            updateAlertTable();
            computeStats();
            elAlerts.textContent = 0;
        } catch (err) {
            console.error("Failed to clear data:", err);
        }
    });

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
        // If not enough time has passed or no recent packets, use overall rate or 0
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
        packetTable.innerHTML = ''; // Clear table
        
        // Filter and display last 100 packets
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
            tr.innerHTML = `
                <td>${index}</td>
                <td>${formatTime(p.timestamp)}</td>
                <td>${details.src}</td>
                <td>${details.dst}</td>
                <td><span class="badge ${getBadgeClass(details.proto)}">${details.proto}</span></td>
                <td>${p.length}</td>
                <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px;" title="${details.info}">${details.info}</td>
            `;
            packetTable.appendChild(tr);
        });
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
                
                // Memory cap (10,000 packets)
                if (allPackets.length > 10000) {
                    allPackets.splice(0, allPackets.length - 10000);
                }
                
                computeStats();
                updateTable();
            } else {
                // Just compute stats to update packet rate
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
            }
        } catch (err) {
            console.error("Failed to fetch alerts:", err);
        }
    }

    function updateAlertTable() {
        alertTable.innerHTML = '';
        const sorted = allAlerts.slice().sort((a, b) => b.timestamp - a.timestamp);
        
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

    setInterval(() => {
        fetchPackets();
        fetchSessions();
        fetchAlerts();
    }, updateIntervalMs);
});
