document.addEventListener('DOMContentLoaded', () => {
    const analyzeForm = document.getElementById('analyzeForm');
    const domainInput = document.getElementById('domainInput');
    const clearBtn = document.getElementById('clearBtn');
    const inputError = document.getElementById('inputError');

    const loadingState = document.getElementById('loadingState');
    const resultsSection = document.getElementById('resultsSection');

    const statusBadge = document.getElementById('statusBadge');
    const resDomain = document.getElementById('resDomain');
    const resNormDomain = document.getElementById('resNormDomain');
    const resReason = document.getElementById('resReason');

    const resTiSource = document.getElementById('resTiSource');
    const resTiStatus = document.getElementById('resTiStatus');
    const resTiMalicious = document.getElementById('resTiMalicious');

    const resMlClass = document.getElementById('resMlClass');

    const probBenignVal = document.getElementById('probBenignVal');
    const probDgaVal = document.getElementById('probDgaVal');
    const probTunnelVal = document.getElementById('probTunnelVal');

    const barBenign = document.getElementById('barBenign');
    const barDga = document.getElementById('barDga');
    const barTunnel = document.getElementById('barTunnel');

    // Handle Form Submission
    analyzeForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const domain = domainInput.value.trim();

        // Frontend validation
        if (!domain) {
            inputError.textContent = "Please enter a valid domain name.";
            inputError.style.display = 'block';
            return;
        }

        inputError.style.display = 'none';
        resultsSection.style.display = 'none';
        loadingState.style.display = 'block';

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain: domain })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || "Error analyzing domain.");
            }

            const data = await response.json();
            renderResults(data);

        } catch (err) {
            inputError.textContent = err.message || "An unexpected network error occurred.";
            inputError.style.display = 'block';
        } finally {
            loadingState.style.display = 'none';
        }
    });

    // Handle Clear Button
    clearBtn.addEventListener('click', () => {
        domainInput.value = '';
        inputError.style.display = 'none';
        resultsSection.style.display = 'none';
        loadingState.style.display = 'none';
    });

    // Render Results from API Response
    function renderResults(data) {
        // Status Badge
        statusBadge.className = 'status-badge';
        if (data.final_status === 'ALLOW') {
            statusBadge.classList.add('status-allow');
            statusBadge.innerHTML = '&#10003; ALLOW';
        } else {
            statusBadge.classList.add('status-block');
            statusBadge.innerHTML = '&#10005; BLOCK';
        }

        // Domain Info & Reason
        resDomain.textContent = data.domain;
        resNormDomain.textContent = data.normalized_domain;
        resReason.textContent = data.reason;

        // Threat Intelligence Info
        const ti = data.threat_intelligence || {};
        resTiSource.textContent = ti.source || 'URLhaus by abuse.ch';
        resTiStatus.textContent = ti.status || 'not_found';
        resTiMalicious.textContent = ti.known_malicious ? 'True (Malicious Indicator)' : 'False (No Indicator)';

        // ML Prediction Info
        const ml = data.ml_prediction || {};
        resMlClass.textContent = ml.class || 'N/A';

        // ML Probabilities
        const probs = ml.probabilities || {};
        const pBenign = ((probs['Benign'] || 0) * 100).toFixed(2);
        const pDga = ((probs['DGA'] || 0) * 100).toFixed(2);
        const pTunnel = ((probs['DNS Tunnelling'] || 0) * 100).toFixed(2);

        probBenignVal.textContent = `${pBenign}%`;
        probDgaVal.textContent = `${pDga}%`;
        probTunnelVal.textContent = `${pTunnel}%`;

        barBenign.style.width = `${pBenign}%`;
        barDga.style.width = `${pDga}%`;
        barTunnel.style.width = `${pTunnel}%`;

        resultsSection.style.display = 'block';
    }
});
