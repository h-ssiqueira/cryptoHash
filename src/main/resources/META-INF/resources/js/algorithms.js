function getAlgorithms() {
    fetch('/api/v1/algorithms')
        .then(response => {
            if(!response.ok) {
                throw new Error('Could not retrieve algorithms, server might be down!')
            }
            return response.json();
        })
        .then(responseBody => {
            const dropDownAlgos = document.getElementById('dropdown');
            responseBody.data.algorithms.forEach(algorithm => {
                const op = document.createElement('option');
                op.value = op.textContent = algorithm;
                dropDownAlgos.appendChild(op);
            });
        })
        .catch(error => {
            console.error('Error fetching data: ', error);
            const dropdown = document.getElementById('dropdown');
            dropdown.innerHTML = 'Error';
        });
}

getAlgorithms();