// Fungsi untuk menampilkan toast notifikasi
function showToast(type, message) {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0 show`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="bi ${type === 'success' ? 'bi-check-circle' : 'bi-exclamation-triangle'} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    toastContainer.appendChild(toast);
    
    // Hapus toast setelah 5 detik
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

let isScanning = false;

async function startScan() {
    if (isScanning) {
        showToast('danger', 'A scan is already in progress');
        return;
    }

    isScanning = true; // Tandai bahwa proses sedang berjalan

    const scanButton = document.getElementById('start-scan');
    if (scanButton.disabled) {
        return; // Mencegah pemanggilan ulang jika tombol sudah dinonaktifkan
    }

    scanButton.disabled = true; // Nonaktifkan tombol
    scanButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Scanning...';

    try {
        const ipInput = document.getElementById('scan-ip');
        const progressBar = document.getElementById('scan-progress');
        const fastScanRadio = document.getElementById('fast-scan');
        const fullScanRadio = document.getElementById('full-scan');
        const scanType = fastScanRadio.checked ? 'fast' : fullScanRadio.checked ? 'full' : null;
        if (!scanType) {
            showToast('danger', 'Please select a scan type');
            return;
        }

        // Dapatkan opsi scan dari form
        const portRange = fullScanRadio.checked ? '1-65535' : '1-1024';
        const serviceDetection = document.getElementById('service-detection').checked;
        const osDetection = document.getElementById('os-detection').checked;
        const vulnScan = document.getElementById('vuln-scan').checked;
        const scanOptions = {
            scan_type: scanType,
            port_range: portRange,
            service_detection: serviceDetection,
            os_detection: osDetection,
            vuln_scan: vulnScan
        };
        const resultsContainer = document.getElementById('scan-results');
        
        const ip = ipInput.value.trim();
        if (!ip) {
            showToast('danger', 'Please enter a valid IP address');
            return;
        }
        
        // Validasi format IP
        if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
            showToast('danger', 'Invalid IP address format');
            return;
        }
        
        // Tampilkan progress
        progressBar.style.width = '0%';
        progressBar.classList.remove('d-none');
        resultsContainer.innerHTML = '';
        
        try {
            // Simulasi progress (di real app ini akan update dari WebSocket/API)
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 10;
                if (progress >= 100) {
                    progress = 100;
                    clearInterval(progressInterval);
                }
                progressBar.style.width = `${progress}%`;
                progressBar.setAttribute('aria-valuenow', progress);
                progressBar.textContent = `${Math.round(progress)}%`;
            }, 300);
            
            // Kirim request scan ke backend
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    ip,
                    port_range: portRange,
                    options: {
                        service_detection: serviceDetection,
                        os_detection: osDetection,
                        vulnerability_scan: vulnScan
                    }
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Scan failed');
            }

            const result = await response.json();
            if (result.status === 'success') {
                showToast('success', `Scan completed! Found ${result.open_ports} open ports.`);
                window.location.href = `/results/${result.scan_id}`;
            } else {
                throw new Error(result.message || 'Scan completed with issues');
            }
        } catch (error) {
            console.error('Scan error:', error);
            showToast('danger', error.message || 'Scan failed. See console for details.');
        }
    } catch (error) {
        console.error('Scan error:', error);
    } finally {
        isScanning = false; // Reset status setelah selesai
        scanButton.disabled = false; // Aktifkan kembali tombol setelah selesai
        scanButton.innerHTML = '<i class="bi bi-search me-2"></i>Start Scan';
    }
}

// Event listener untuk halaman scan
if (document.getElementById('scan-form')) {
    document.getElementById('scan-form').addEventListener('submit', (e) => {
        e.preventDefault();
        startScan();
    });
}

// Event listener untuk tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Aktifkan tooltip Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Aktifkan popover
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Copy IP address functionality
    document.getElementById('copyIpBtn').addEventListener('click', function() {
        const ip = '{{ scan.ip }}';
        navigator.clipboard.writeText(ip).then(() => {
            const tooltip = new bootstrap.Tooltip(this, {
                title: 'Copied!',
                trigger: 'manual'
            });
            tooltip.show();
            setTimeout(() => tooltip.hide(), 1000);
        });
    });
});