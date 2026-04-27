// DSEC Dashboard Logic

const API_BASE = "/api";

// Initialize Time
function updateTime() {
    const now = new Date();
    document.getElementById('current-time').innerText = now.toISOString().replace('T', ' ').substr(0, 19) + " UTC";
}
setInterval(updateTime, 1000);
updateTime();

// Fetch Stats
async function fetchStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();
        
        document.getElementById('stat-nodes').innerText = data.knowledge_graph.nodes;
        document.getElementById('stat-edges').innerText = data.knowledge_graph.edges;
        document.getElementById('stat-routines').innerText = data.total_routines;
    } catch (err) {
        console.error("Stats fetch failed", err);
    }
}

// Fetch Sessions
async function fetchSessions() {
    try {
        const res = await fetch(`${API_BASE}/sessions`);
        const data = await res.json();
        
        const list = document.getElementById('sessions-list');
        list.innerHTML = '';
        
        data.forEach(s => {
            const div = document.createElement('div');
            div.className = 'session-item';
            div.innerHTML = `
                <div class="name">${s.name}</div>
                <div class="preview">${s.last_msg}</div>
            `;
            list.appendChild(div);
        });
    } catch (err) {
        console.error("Sessions fetch failed", err);
    }
}

// Initialize Graph
async function initGraph() {
    try {
        const res = await fetch(`${API_BASE}/graph`);
        const data = await res.json();
        
        const nodes = [];
        const edges = [];
        
        const nodeMap = data.nodes || {};
        Object.keys(nodeMap).forEach(id => {
            const n = nodeMap[id];
            nodes.push({
                id: id,
                label: id,
                title: JSON.stringify(n.metadata, null, 2),
                color: {
                    background: '#0f172a',
                    border: '#00afff',
                    highlight: '#00d2ff'
                },
                font: { color: '#f8fafc' }
            });
        });
        
        data.edges.forEach(e => {
            edges.push({
                from: e.from,
                to: e.to,
                label: e.relation,
                arrows: 'to',
                color: '#555555',
                font: { align: 'top', color: '#94a3b8', size: 10 }
            });
        });

        const container = document.getElementById('mynetwork');
        const graphData = {
            nodes: new vis.DataSet(nodes),
            edges: new vis.DataSet(edges)
        };
        const options = {
            physics: {
                enabled: true,
                stabilization: true
            },
            interaction: { hover: true }
        };
        new vis.Network(container, graphData, options);
    } catch (err) {
        console.error("Graph init failed", err);
    }
}

// Initial Load
fetchStats();
fetchSessions();
initGraph();

// Refresh cycles
setInterval(fetchStats, 10000);
setInterval(fetchSessions, 30000);
