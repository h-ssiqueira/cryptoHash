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

document.getElementById('hash').addEventListener('click', function() {
    event.preventDefault();
    const txt = document.getElementById('textAreaInput').value;
    const algo = document.getElementById('dropdown').value;
    if(!txt) {
        document.getElementById('textAreaOutput').textContent = 'Insert data in the field above!';
        return;
    }
    if(!algo) {
        document.getElementById('textAreaOutput').textContent = 'Choose one algorithm from dropdown!';
        return;
    }
    fetch(`/api/v1/encrypt?algorithm=${algo}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: txt})
    })
    .then(response => {
        if(!response.ok) {
            throw new Error('Could not encrypt, server might be down!');
        }
        return response.json();
    })
    .then(responseBody => {
        console.log(responseBody);
        document.getElementById('textAreaOutput').textContent = responseBody.data.passwordEncrypted;
    })
    .catch(err => {
        console.error('Error to hash password: ', err);
    });
});

getAlgorithms();