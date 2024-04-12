from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route('/webhook', methods=['POST'])
def github_webhook():
    data = request.json
    if data['ref'] == 'refs/heads/main':
        # Perform git pull
        subprocess.run(['git', 'pull'])
        return 'Git pull successful', 200
    return 'Webhook received but no action taken', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
