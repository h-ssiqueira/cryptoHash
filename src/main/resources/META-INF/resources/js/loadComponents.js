function loadComponent(url, elementId) {
    fetch(url)
        .then(response => response.text())
        .then(data => {
            document.getElementById(elementId).innerHTML = data;
            if(elementId === 'footer') {
                document.getElementById('currYear').textContent = new Date().getFullYear();
            }
        });
}

document.addEventListener('DOMContentLoaded', () => {
    loadComponent('../html/nav.html', 'nav');
    loadComponent('../html/footer.html', 'footer');
});
