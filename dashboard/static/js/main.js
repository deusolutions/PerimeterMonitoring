function initSearch(searchInputId, tableId, columns) {
    document.addEventListener('DOMContentLoaded', function() {
        const searchInput = document.getElementById(searchInputId);
        const table = document.getElementById(tableId);
        if (!searchInput || !table) return;

        const rows = table.getElementsByTagName('tr');

        let timeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                const query = this.value.toLowerCase().trim();
                for (let i = 1; i < rows.length; i++) {
                    let match = false;
                    for (let col of columns) {
                        const text = rows[i].cells[col.column].textContent.toLowerCase();
                        if (text.includes(query)) {
                            match = true;
                            break;
                        }
                    }
                    rows[i].style.display = match ? '' : 'none';
                }
            }, 300);
        });
    });
}