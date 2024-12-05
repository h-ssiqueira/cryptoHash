document.getElementById('match').addEventListener('click', function () {
    event.preventDefault();
    const rawPass = document.getElementById('rawPassword').value;
    const hashedPass = document.getElementById('hashedPassword').value;
    const algo = document.getElementById('dropDown').value;
    if(!rawPass || !hashedPass) {
        console.log('Insert the necessary data!');
        return;
    }
    if(!algo) {
        console.log('Choose an algorithm!');
        return;
    }
    fetch(`/api/v1/match?algorithm=${algo}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rawPassword: rawPass, encryptedPassword: hashedPass})
    })
        .then(response => {
            if(!response.ok || !response.status != 400) {
                throw new Error('Could not match passwords, server might be down!');
            }
            return response.json();
        })
        .catch(err => {
            console.log('Error trying to match password: ', err);
        })
});