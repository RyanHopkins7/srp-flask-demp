(async () => {
    document.getElementById('register-button').addEventListener('click', async () => {
        const username = document.getElementById('register-username').value;
        const password = document.getElementById('register-password').value;

        const client = new jsrp.client();

        client.init({ username: username, password: password }, async function () {
            client.createVerifier(async function(err, result) {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'salt': result.salt,
                        'verifier': result.verifier
                    })
                });

                alert(`Registration completed. Server response: ${(await response.json()).result}`);
            });
        });
    });

    document.getElementById('authenticate-button').addEventListener('click', async () => {
        const username = document.getElementById('authenticate-username').value;
        const password = document.getElementById('authenticate-password').value;

        const client = new jsrp.client();

        client.init({ username: username, password: password }, async function() {
            const A = client.getPublicKey();
            
            const response = await fetch('/start-authentication', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'username': username, 
                    'A': A
                })
            });

            const { s, B } = await response.json();

            client.setSalt(s);
            client.setServerPublicKey(B);

            console.log('Shared key: ', client.getSharedKey());

            const M = client.getProof();

            const verifyResponse = await fetch('/verify-session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    'M': M
                })
            });

            if (!verifyResponse.ok) {
                const error = await verifyResponse.json();
                alert(`Authentication failed. Server response: ${error.error}`);
                return;
            }

            const verifyResult = await verifyResponse.json();
            
            const HAMK = verifyResult.HAMK;
            if (client.checkServerProof(HAMK)) {
                alert(`Authentication completed. Server response: ${verifyResult.result}`);
            } else {
                alert('Server proof verification failed.');
                return;
            }

            console.log('Server proof verified successfully.');
        });
    });
})();