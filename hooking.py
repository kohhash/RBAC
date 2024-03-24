from flask import Flask, request

app = Flask(__name__)


@app.route('/webhook', methods=['POST'])
def github_webhook():
    data = request.json
    # Process the incoming webhook payload here
    print('Webhook received:', data)
    return 'Webhook received successfully', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
