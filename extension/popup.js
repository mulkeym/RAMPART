const views = {
    enroll: document.getElementById('enroll-view'),
    enrolled: document.getElementById('enrolled-view'),
    settings: document.getElementById('settings-view'),
};

function setStatus(el, color, text) {
    el.textContent = '';
    const dot = document.createElement('span');
    dot.className = 'dot ' + color;
    const span = document.createElement('span');
    span.textContent = text;
    el.appendChild(dot);
    el.appendChild(span);
}

function showView(name) {
    Object.values(views).forEach(v => v.classList.add('hidden'));
    views[name].classList.remove('hidden');
}

chrome.storage.sync.get(['rampartUrl', 'apiKey', 'enabled', 'enrolled', 'clientId', 'groupName', 'userEmail'], (data) => {
    document.getElementById('url').value = data.rampartUrl || 'http://localhost:8080';
    document.getElementById('settings-url').value = data.rampartUrl || 'http://localhost:8080';
    document.getElementById('settings-apiKey').value = data.apiKey || '';
    if (data.enrolled && data.apiKey) {
        document.getElementById('enabled').checked = data.enabled !== false;
        document.getElementById('enrolled-user').textContent = data.userEmail || 'Unknown';
        document.getElementById('enrolled-group').textContent = data.groupName || 'Unknown';
        document.getElementById('enrolled-client').textContent = data.clientId || '';
        showView('enrolled');
    } else {
        showView('enroll');
    }
});

let userEmail = '';
let userName = '';
try {
    chrome.identity.getProfileUserInfo({accountStatus: 'ANY'}, (info) => {
        if (info && info.email) {
            userEmail = info.email;
            userName = info.email.split('@')[0];
        }
    });
} catch(e) {}

function getDeviceId() {
    let id = localStorage.getItem('rampart-device-id');
    if (!id) {
        id = 'chrome-' + Math.random().toString(36).substring(2, 10);
        localStorage.setItem('rampart-device-id', id);
    }
    return id;
}

document.getElementById('enrollBtn').addEventListener('click', async () => {
    const url = document.getElementById('url').value.replace(/\/+$/, '');
    const groupKey = document.getElementById('groupKey').value.trim();
    const status = document.getElementById('enroll-status');
    if (!url || !groupKey) {
        setStatus(status, 'red', 'URL and group key required');
        return;
    }
    // Check for manual email entry
    const manualEmail = document.getElementById('manualEmail').value.trim();
    if (manualEmail) {
        userEmail = manualEmail;
        userName = manualEmail.split('@')[0];
    }

    setStatus(status, 'gray', 'Checking identity...');
    try {
        // Try mTLS identity server for CAC-based identity
        let identityNonce = '';
        let identityResolved = false;
        try {
            const idUrl = url.replace(/:\d+$/, ':8443');
            const idData = await chrome.runtime.sendMessage({ type: 'identityCheck', url: idUrl });
            if (idData && idData.nonce && idData.identity) {
                identityNonce = idData.nonce;
                userEmail = idData.san || idData.identity;
                userName = idData.cn || idData.identity;
                identityResolved = true;
                setStatus(status, 'green', 'Identity: ' + (idData.identity || ''));
            }
        } catch (e) {
            // Identity server not available
        }

        // If no identity from cert or Chrome, prompt for email
        if (!identityResolved && !userEmail) {
            document.getElementById('manual-identity').classList.remove('hidden');
            setStatus(status, 'red', 'Enter your email address to enroll');
            return;
        }

        setStatus(status, 'gray', 'Enrolling...');
        const data = await chrome.runtime.sendMessage({
            type: 'enroll',
            url: url,
            enrollment_key: groupKey,
            user_name: userName,
            user_email: userEmail,
            device_id: getDeviceId(),
            identity_nonce: identityNonce
        });
        if (data.status === 'enrolled' || data.status === 're-enrolled') {
            chrome.storage.sync.set({
                rampartUrl: url, apiKey: data.api_key, clientId: data.client_id,
                groupName: data.group_name, groupId: data.group_id,
                userEmail: userEmail, enrolled: true, enabled: true
            }, () => {
                document.getElementById('enrolled-user').textContent = userEmail;
                document.getElementById('enrolled-group').textContent = data.group_name;
                document.getElementById('enrolled-client').textContent = data.client_id;
                document.getElementById('enabled').checked = true;
                showView('enrolled');
            });
        } else {
            setStatus(status, 'red', data.message || 'Enrollment failed');
        }
    } catch (e) {
        setStatus(status, 'red', 'Cannot connect: ' + e.message);
    }
});

document.getElementById('reenrollBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['rampartUrl'], (data) => {
        document.getElementById('url').value = data.rampartUrl || 'http://localhost:8080';
        document.getElementById('groupKey').value = '';
        showView('enroll');
    });
});

document.getElementById('enabled').addEventListener('change', (e) => {
    chrome.storage.sync.set({ enabled: e.target.checked });
});

document.getElementById('settingsBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['rampartUrl', 'apiKey'], (data) => {
        document.getElementById('settings-url').value = data.rampartUrl || '';
        document.getElementById('settings-apiKey').value = data.apiKey || '';
        showView('settings');
    });
});

document.getElementById('saveSettingsBtn').addEventListener('click', () => {
    const status = document.getElementById('settings-status');
    chrome.storage.sync.set({
        rampartUrl: document.getElementById('settings-url').value.replace(/\/+$/, ''),
        apiKey: document.getElementById('settings-apiKey').value,
    }, () => {
        setStatus(status, 'green', 'Saved');
    });
});

document.getElementById('testBtn').addEventListener('click', async () => {
    const status = document.getElementById('settings-status');
    const url = document.getElementById('settings-url').value.replace(/\/+$/, '');
    setStatus(status, 'gray', 'Testing...');
    try {
        const result = await chrome.runtime.sendMessage({ type: 'healthCheck', url: url });
        if (result && result.status === 'ok') {
            setStatus(status, 'green', 'Connected');
        } else {
            setStatus(status, 'red', result ? (result.error || 'Failed') : 'No response');
        }
    } catch (e) {
        setStatus(status, 'red', e.message);
    }
});

document.getElementById('backBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['enrolled', 'apiKey'], (data) => {
        showView(data.enrolled && data.apiKey ? 'enrolled' : 'enroll');
    });
});

document.getElementById('unenrollBtn').addEventListener('click', () => {
    chrome.storage.sync.set({
        apiKey: '', enrolled: false, clientId: '', groupName: '', groupId: '', userEmail: ''
    }, () => {
        showView('enroll');
    });
});
