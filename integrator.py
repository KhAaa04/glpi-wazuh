import base64
import requests
from flask import Flask, request
import datetime
import json

app = Flask(__name__)

GLPI_URL = 'http://172.31.247.85:8081/apirest.php/'
GLPI_APP_TOKEN = 'sP5gKzyCBDWi9ALWuT6o8ZJPT4yzdyGGtmDR55w6'  # Ваш App Token
GLPI_USER = 'glpi'
GLPI_PASSWORD = 'glpi'

def get_glpi_session():
    """Получение сессии через Basic Auth (логин и пароль в заголовке)"""
    headers = {
        'Content-Type': 'application/json',
        'App-Token': GLPI_APP_TOKEN
    }
    # Формируем Basic Auth из логина и пароля
    credentials = f"{GLPI_USER}:{GLPI_PASSWORD}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    headers['Authorization'] = f'Basic {encoded_credentials}'
    
    # GET-запрос БЕЗ тела
    response = requests.get(GLPI_URL + 'initSession', headers=headers)
    
    if response.status_code == 200:
        session_token = response.json()['session_token']
        print(f"[{datetime.datetime.now()}] Сессия получена")
        return session_token
    else:
        print(f"[{datetime.datetime.now()}] Ошибка авторизации: {response.text}")
        return None

def create_ticket(session_token, title, content):
    headers = {
        'Content-Type': 'application/json',
        'Session-Token': session_token,
        'App-Token': GLPI_APP_TOKEN
    }
    data = {
        'input': {
            'name': title,
            'content': content,
            'type': 1,        # 1 - Инцидент
            'status': 1,      # 1 - Новая
            'urgency': 3      # 3 - Высокая срочность
        }
    }
    response = requests.post(GLPI_URL + 'Ticket', headers=headers, data=json.dumps(data))
    return response.status_code, response.text

@app.route('/webhook', methods=['POST'])
def wazuh_webhook():
    alert = request.json
    if not alert:
        return 'No data', 400

    print(f"[{datetime.datetime.now()}] Полный алерт: {json.dumps(alert, indent=2)}")

    rule_level = alert.get('rule', {}).get('level', 0)
    rule_desc = alert.get('rule', {}).get('description', 'Unknown')
    agent_ip = alert.get('agent', {}).get('ip', 'Unknown')
    timestamp = alert.get('timestamp', '')

    print(f"[{datetime.datetime.now()}] Уровень алерта: {rule_level}")

    if rule_level >= 1:
        session = get_glpi_session()
        if session:
            title = f"[Инцидент ИБ] {rule_desc}"
            content = f"Источник: {agent_ip}\nВремя: {timestamp}\nОписание: {rule_desc}\nУровень: {rule_level}"
            status, response_text = create_ticket(session, title, content)
            print(f"[{datetime.datetime.now()}] Ответ GLPI: {status} - {response_text}")
            if status == 201 or status == 200:
                return 'Ticket created', 201
            else:
                return 'Ticket creation failed', 500
        else:
            return 'Auth failed', 500

    return 'Event ignored', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
