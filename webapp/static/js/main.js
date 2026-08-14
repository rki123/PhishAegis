let riskGaugeChart = null;
let radarProfileChart = null;
let featureBarChart = null;
let modelsCompareChart = null;

document.addEventListener('DOMContentLoaded', () => {
    fetchModels();

    const form = document.getElementById('url-form');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('url-input').value.trim();
        const model = document.getElementById('model-select').value;
        if (url) {
            await analyzeUrl(url, model);
        }
    });
});

async function fetchModels() {
    try {
        const response = await fetch('/api/v1/models');
        const data = await response.json();
        
        const select = document.getElementById('model-select');
        select.innerHTML = '';
        
        data.models.forEach(model => {
            const option = document.createElement('option');
            option.value = model.id;
            option.textContent = model.name;
            if(model.id === 'hybrid') option.selected = true;
            select.appendChild(option);
        });
    } catch (error) {
        console.error("Failed to load models", error);
    }
}

function triggerShieldActivation(active) {
    const heroShieldWrapper = document.getElementById('hero-shield-wrapper');
    const headerShieldWrapper = document.getElementById('header-shield-wrapper');
    const inputGroupContainer = document.getElementById('input-group-container');
    const btnText = document.getElementById('btn-text');
    const btnIcon = document.getElementById('btn-icon');

    if (active) {
        // Activate glowing shield shine and laser scan
        heroShieldWrapper.classList.add('active');
        headerShieldWrapper.classList.add('active');
        inputGroupContainer.classList.add('scanning');
        if (btnText) btnText.textContent = 'Scanning...';
        if (btnIcon) btnIcon.textContent = '🛰️';
    } else {
        // Deactivate scanner effects
        heroShieldWrapper.classList.remove('active');
        headerShieldWrapper.classList.remove('active');
        inputGroupContainer.classList.remove('scanning');
        if (btnText) btnText.textContent = 'Analyze URL';
        if (btnIcon) btnIcon.textContent = '⚡';
    }
}

async function analyzeUrl(url, modelId) {
    const btn = document.getElementById('check-btn');
    btn.disabled = true;
    
    // Trigger Shield Activation Shine & Laser Beam Scan
    triggerShieldActivation(true);
    
    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url, model: modelId })
        });
        
        const data = await response.json();
        if (data.error) {
            alert(data.error);
            return;
        }
        
        displayResults(data);
    } catch (error) {
        console.error("Error analyzing URL:", error);
        alert("An error occurred during analysis.");
    } finally {
        triggerShieldActivation(false);
        btn.disabled = false;
    }
}

function displayResults(data) {
    const resultSection = document.getElementById('result-section');
    resultSection.classList.remove('hidden');
    
    // Update Badge & Verdict
    const badge = document.getElementById('status-badge');
    badge.textContent = data.status;
    badge.className = `verdict-badge ${data.status}`;
    
    document.getElementById('scanned-url-text').textContent = data.url;
    
    const confidenceText = document.getElementById('safety-score-text');
    if (data.status === 'SAFE') {
        confidenceText.textContent = `${data.safety_score}% Confidence (Safe)`;
    } else {
        confidenceText.textContent = `${data.risk_score}% Phishing Risk Detected`;
    }

    // Engine Scores
    document.getElementById('cnn-score-val').textContent = data.cnn_score !== null ? `${data.cnn_score}% Risk` : 'N/A';
    document.getElementById('ml-score-val').textContent = data.ml_score !== null ? `${data.ml_score}% Risk` : 'N/A';

    // Gauge Center Text
    document.getElementById('gauge-center-val').textContent = `${data.risk_score}%`;

    // Flags Badges
    const flagsList = document.getElementById('flags-list');
    flagsList.innerHTML = '';
    data.flags.forEach(flag => {
        const span = document.createElement('span');
        span.className = 'flag-badge';
        span.textContent = flag;
        flagsList.appendChild(span);
    });

    // Detailed Reasons & Explanations
    const reasonsContainer = document.getElementById('reasons-container');
    reasonsContainer.innerHTML = '';
    if (data.reasons && data.reasons.length > 0) {
        data.flags.forEach((flag, idx) => {
            const card = document.createElement('div');
            card.className = `reason-card ${data.status}`;
            
            const title = document.createElement('div');
            title.className = 'reason-title';
            title.textContent = `• ${flag}`;
            
            const desc = document.createElement('div');
            desc.className = 'reason-desc';
            desc.textContent = data.reasons[idx] || "Detected anomaly during feature extraction.";
            
            card.appendChild(title);
            card.appendChild(desc);
            reasonsContainer.appendChild(card);
        });
    }

    // Raw Statistics Grid
    const statsContainer = document.getElementById('stats-container');
    statsContainer.innerHTML = '';
    if (data.raw_stats) {
        Object.entries(data.raw_stats).forEach(([key, value]) => {
            const chip = document.createElement('div');
            chip.className = 'stat-chip';
            
            const label = document.createElement('span');
            label.className = 'stat-label';
            label.textContent = key;
            
            const val = document.createElement('span');
            val.className = 'stat-value';
            val.textContent = value;
            
            chip.appendChild(label);
            chip.appendChild(val);
            statsContainer.appendChild(chip);
        });
    }
    
    // Update All 4 Analytics Charts
    updateCharts(data);

    // Scroll to results smoothly
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function updateCharts(data) {
    updateGaugeChart(data.risk_score);
    updateRadarChart(data.radar_metrics, data.status);
    updateFeatureChart(data.feature_contributions);
    updateModelsCompareChart(data.all_model_scores);
}

// 1. Risk Gauge Chart
function updateGaugeChart(riskScore) {
    const ctx = document.getElementById('riskGauge').getContext('2d');
    if (riskGaugeChart) riskGaugeChart.destroy();
    
    let gaugeColor = '#10b981';
    if (riskScore > 65) gaugeColor = '#f43f5e';
    else if (riskScore > 35) gaugeColor = '#f59e0b';

    riskGaugeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Risk', 'Safe'],
            datasets: [{
                data: [riskScore, 100 - riskScore],
                backgroundColor: [gaugeColor, 'rgba(255, 255, 255, 0.08)'],
                borderWidth: 0
            }]
        },
        options: {
            rotation: -90,
            circumference: 180,
            cutout: '82%',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        }
    });
}

// 2. Threat Vector Radar Profile Chart
function updateRadarChart(radarMetrics, status) {
    const ctx = document.getElementById('radarChart').getContext('2d');
    if (radarProfileChart) radarProfileChart.destroy();

    const labels = Object.keys(radarMetrics || {});
    const values = Object.values(radarMetrics || {});

    let fillColor = 'rgba(59, 130, 246, 0.25)';
    let strokeColor = '#3b82f6';

    if (status === 'CRITICAL') {
        fillColor = 'rgba(244, 63, 94, 0.25)';
        strokeColor = '#f43f5e';
    } else if (status === 'WARNING') {
        fillColor = 'rgba(245, 158, 11, 0.25)';
        strokeColor = '#f59e0b';
    } else if (status === 'SAFE') {
        fillColor = 'rgba(16, 185, 129, 0.25)';
        strokeColor = '#10b981';
    }

    radarProfileChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Intensity',
                data: values,
                backgroundColor: fillColor,
                borderColor: strokeColor,
                borderWidth: 2,
                pointBackgroundColor: strokeColor,
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                r: {
                    angleLines: { color: 'rgba(255, 255, 255, 0.1)' },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    pointLabels: { color: '#94a3b8', font: { size: 10, weight: '600' } },
                    ticks: { display: false, min: 0, max: 100 }
                }
            }
        }
    });
}

// 3. Feature Risk Contribution Chart
function updateFeatureChart(contributions) {
    const ctx = document.getElementById('featureChart').getContext('2d');
    if (featureBarChart) featureBarChart.destroy();
    
    const labels = Object.keys(contributions || {});
    const data = Object.values(contributions || {});
    
    const backgroundColors = data.map(value => value > 0 ? 'rgba(244, 63, 94, 0.85)' : 'rgba(16, 185, 129, 0.85)');
    
    featureBarChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Risk Contribution',
                data: data,
                backgroundColor: backgroundColors,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.08)' },
                    ticks: { color: '#94a3b8' },
                    title: { display: true, text: 'Contribution Score (Red = Risk, Green = Safe)', color: '#94a3b8' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#e2e8f0' }
                }
            }
        }
    });
}

// 4. All Models Prediction Score Bar Chart
function updateModelsCompareChart(modelScores) {
    const ctx = document.getElementById('modelsCompareChart').getContext('2d');
    if (modelsCompareChart) modelsCompareChart.destroy();

    const labels = Object.keys(modelScores || {});
    const data = Object.values(modelScores || {});

    const colors = ['#60a5fa', '#a78bfa', '#f472b6', '#fbbf24', '#34d399'];

    modelsCompareChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Risk %',
                data: data,
                backgroundColor: colors,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#e2e8f0', font: { size: 10 } }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.08)' },
                    ticks: { color: '#94a3b8' },
                    min: 0,
                    max: 100,
                    title: { display: true, text: 'Predicted Risk Score (%)', color: '#94a3b8' }
                }
            }
        }
    });
}
