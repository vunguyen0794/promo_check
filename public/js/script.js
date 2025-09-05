// ... existing code ...

// Autocomplete for SKU search
function initAutocomplete() {
    const searchInput = document.querySelector('input[name="sku"]');
    if (!searchInput) return;
    
    let timeoutId;
    
    searchInput.addEventListener('input', function(e) {
        clearTimeout(timeoutId);
        const value = e.target.value.trim();
        
        if (value.length < 2) {
            hideAutocomplete();
            return;
        }
        
        timeoutId = setTimeout(async () => {
            try {
                const response = await fetch(`/api/skus?q=${encodeURIComponent(value)}`);
                const data = await response.json();
                showAutocomplete(data);
            } catch (error) {
                console.error('Autocomplete error:', error);
            }
        }, 300);
    });
    
    // Hide autocomplete when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.autocomplete-container')) {
            hideAutocomplete();
        }
    });
}

function showAutocomplete(items) {
    hideAutocomplete();
    
    const searchInput = document.querySelector('input[name="sku"]');
    const container = document.createElement('div');
    container.className = 'autocomplete-results';
    
    items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'autocomplete-item';
        div.textContent = `${item.sku} - ${item.product_name} - ${item.brand}`;
        div.dataset.sku = item.sku;
        
        div.addEventListener('click', function() {
            searchInput.value = item.sku;
            hideAutocomplete();
            searchInput.closest('form').submit();
        });
        
        container.appendChild(div);
    });
    
    searchInput.parentNode.appendChild(container);
}

function hideAutocomplete() {
    const existing = document.querySelector('.autocomplete-results');
    if (existing) {
        existing.remove();
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // ... existing code ...
    initAutocomplete();
});