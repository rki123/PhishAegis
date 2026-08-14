document.addEventListener('DOMContentLoaded', () => {
    // Get active browser tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs || tabs.length === 0) {
            showError("Could not detect active tab.");
            return;
        }
        
        const activeUrl = tabs[0].url;
        document.getElementById('url-text').textContent = activeUrl;
        
        // Skip internal browser pages
        if (activeUrl.startsWith('chrome://') || activeUrl.startsWith('edge://') || activeUrl.startsWith('about:')) {
            showError("Browser system page skipped.");
            return;
        }

        analyzeUrl(activeUrl);
    });
});

async function analyzeUrl(url) {
    try {
        const response = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url, model: 'hybrid' })
        });
        
        const data = await response.json();
        
        if (data.error) {
            showError(data.error);
            return;
        }
        
        displayResults(data);
    } catch (error) {
        console.error("API Error:", error);
        showError("Ensure local server is running on port 5000.");
    }
}

function displayResults(data) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('result').classList.remove('hidden');
    
    // Status Badge
    const badge = document.getElementById('status-badge');
    badge.textContent = data.status;
    badge.className = `verdict-badge ${data.status}`;
    
    // Risk score
    document.getElementById('risk-score').textContent = `${data.risk_score}%`;
    
    // Threat flags
    const flagsList = document.getElementById('flags-list');
    flagsList.innerHTML = '';
    
    if (data.flags && data.flags.length > 0) {
        data.flags.forEach(flag => {
            const span = document.createElement('span');
            span.className = 'flag-badge';
            span.textContent = flag;
            flagsList.appendChild(span);
        });
    } else {
        const span = document.createElement('span');
        span.className = 'flag-badge';
        span.style.color = '#10b981';
        span.textContent = "Clean Structural Signature";
        flagsList.appendChild(span);
    }
}

function showError(msg) {
    const loading = document.getElementById('loading');
    loading.innerHTML = `<span style="color: #f43f5e; font-weight: 700;">⚠️ ${msg}</span>`;
}
